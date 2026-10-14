'use strict';
/**
 * VoltMaster - AI Customer Support endpoints (Render backend).
 *
 * Identity is ALWAYS proven on the server:
 *   - Google user  : Firebase ID token (Authorization: Bearer <idToken>), verified email.
 *   - Phone user   : signed session token (X-VM-Session) issued by /verify-otp after a
 *                    correct OTP. localStorage alone is never trusted.
 * The user id is never taken from the request body.
 */
const crypto = require('crypto');

const DAY = 24 * 60 * 60 * 1000;
const COMPLAINT_TYPES = [
  'Partner Behaviour', 'Late Arrival', 'Poor Service', 'Wrong Service',
  'Payment Issue', 'Damage', 'Refund Issue', 'Other',
];

const last10 = (s) => String(s || '').replace(/\D/g, '').slice(-10);
const lower = (s) => String(s || '').trim().toLowerCase();
const R = (status, body) => ({ status, body });
const cleanText = (v, max) => String(v == null ? '' : v).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '').trim().slice(0, max);
const validId = (v) => typeof v === 'string' && /^[A-Za-z0-9_-]{5,64}$/.test(v);
const toDate = (v) => (v && typeof v.toDate === 'function' ? v.toDate() : v instanceof Date ? v : null);
const iso = (v) => { const d = toDate(v); return d ? d.toISOString() : null; };

// ---------- signed tokens (HMAC, node built-in crypto only) ----------
function signToken(payload, secret) {
  if (!secret) return null;
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', secret).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(token, secret, nowMs) {
  if (!secret || typeof token !== 'string') return null;
  const i = token.indexOf('.');
  if (i < 1) return null;
  const body = token.slice(0, i);
  const a = Buffer.from(token.slice(i + 1));
  const b = Buffer.from(crypto.createHmac('sha256', secret).update(body).digest('base64url'));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  let p;
  try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch (e) { return null; }
  if (!p || typeof p.exp !== 'number' || p.exp < nowMs) return null;
  return p;
}
// Called by /verify-otp after a CORRECT otp. Returns null if SESSION_SECRET is not set.
function signSession(phone, secret, nowMs = Date.now(), ttlMs = 30 * DAY) {
  const p = last10(phone);
  if (!/^\d{10}$/.test(p)) return null;
  return signToken({ t: 'sess', p, exp: nowMs + ttlMs }, secret);
}

function createSupport(deps) {
  const {
    db, auth, secret,
    adminEmails = [],
    overdueHours = 48,
    triggerRefund,                       // async (bookingId) => boolean
    serverTimestamp,                     // () => FieldValue.serverTimestamp()
    now = () => Date.now(),
    randomTicket = () => String(crypto.randomInt(100000, 1000000)),
  } = deps;

  // ---------- identity ----------
  async function verifyBearer(headers) {
    const authz = String((headers && headers.authorization) || '');
    if (!/^Bearer\s+/i.test(authz)) return null;
    try { return await auth.verifyIdToken(authz.replace(/^Bearer\s+/i, '')); } catch (e) { return null; }
  }
  const isGoogle = (d) => !!(d && d.email && d.email_verified && d.firebase && d.firebase.sign_in_provider === 'google.com');

  async function identify(headers) {
    const decoded = await verifyBearer(headers);
    const sess = headers && headers['x-vm-session'] ? verifyToken(headers['x-vm-session'], secret, now()) : null;
    const phone10 = sess && sess.t === 'sess' && /^\d{10}$/.test(sess.p) ? sess.p : '';
    const google = isGoogle(decoded);
    if (!google && !phone10) return null;      // an anonymous Firebase token alone is NOT an identity
    const ids = new Set();
    if (decoded && decoded.uid) ids.add(decoded.uid);
    if (phone10) { ids.add(phone10); ids.add('91' + phone10); }
    return {
      subject: google ? 'g:' + decoded.uid : 'p:' + phone10,
      uid: decoded ? decoded.uid : null,
      email: google ? lower(decoded.email) : '',
      google, phone10, ids,
    };
  }
  const guard = (fn) => async (headers, body) => {
    const id = await identify(headers);
    if (!id) return R(401, { error: 'unauthorized' });
    return fn(id, body || {});
  };

  // ownership: STRICT (userId must be one of the caller's own verified ids) for cancel;
  // VIEW (also booking.phone == verified phone) for read-only refund/complaint lookups.
  const strictOwner = (id, b) => id.ids.has(String(b.userId || ''));
  const viewOwner = (id, b) => strictOwner(id, b) || (!!id.phone10 && last10(b.phone) === id.phone10);

  const bookingsCol = () => db.collection('serviceRequests');
  const refundsCol = () => db.collection('refunds');
  const complaintsCol = () => db.collection('complaints');

  async function getOwnedBooking(id, bookingId, strict) {
    if (!validId(bookingId)) return null;
    const s = await bookingsCol().doc(bookingId).get();
    if (!s.exists) return null;
    const b = s.data();
    return (strict ? strictOwner(id, b) : viewOwner(id, b)) ? b : null;
  }

  // ---------- 1) my bookings ----------
  const bookings = guard(async (id) => {
    const found = new Map();
    const add = (snap) => snap.docs.forEach((d) => found.set(d.id, d.data()));
    add(await bookingsCol().where('userId', 'in', [...id.ids]).get());
    if (id.phone10) add(await bookingsCol().where('phone', 'in', [id.phone10, '91' + id.phone10]).get());
    const list = [...found.entries()].map(([bid, b]) => ({
      id: bid, service: b.service || '', status: b.status || '', amount: b.amount || 0,
      createdAt: iso(b.createdAt),
      canCancel: strictOwner(id, b) && lower(b.status) === 'pending',
    }));
    list.sort((x, y) => String(y.createdAt || '').localeCompare(String(x.createdAt || '')));
    return R(200, { bookings: list.slice(0, 20) });
  });

  // ---------- 2) refund status ----------
  const refund = guard(async (id, body) => {
    const b = await getOwnedBooking(id, body.bookingId, false);
    if (!b) return R(404, { error: 'booking_not_found' });
    const rs = await refundsCol().doc(body.bookingId).get();
    const bookingStatus = lower(b.status);
    if (!rs.exists) {
      if (bookingStatus !== 'cancelled') return R(200, { state: 'booking_not_cancelled', suggestComplaint: false });
      if (!b.paymentId) return R(200, { state: 'no_payment_record', suggestComplaint: false });
      return R(200, { state: 'no_refund_record', suggestComplaint: true });
    }
    const r = rs.data();
    const status = lower(r.status || 'pending');
    const out = { refundStatus: status, amount: r.amount || b.amount || 0, requestedAt: iso(r.requestedAt), refundId: r.refundId || '' };
    if (status === 'completed') return R(200, { ...out, state: 'initiated', suggestComplaint: false });
    if (status === 'failed') return R(200, { ...out, state: 'failed', suggestComplaint: true });
    const req = toDate(r.requestedAt);
    const overdue = !!req && now() - req.getTime() > overdueHours * 3600 * 1000;
    return R(200, { ...out, state: overdue ? 'pending_overdue' : 'pending', suggestComplaint: overdue });
  });

  // ---------- 3) cancellation: prepare (no change) -> confirm (changes) ----------
  const cancelPrepare = guard(async (id, body) => {
    const b = await getOwnedBooking(id, body.bookingId, true);
    if (!b) return R(404, { error: 'booking_not_found' });
    if (lower(b.status) !== 'pending') return R(409, { error: 'not_eligible', status: lower(b.status) });
    const confirmToken = signToken({ t: 'cancel', b: body.bookingId, s: id.subject, exp: now() + 5 * 60 * 1000 }, secret);
    if (!confirmToken) return R(503, { error: 'server_not_configured' });
    return R(200, {
      confirmToken, expiresInSec: 300,
      booking: { id: body.bookingId, service: b.service || '', amount: b.amount || 0, createdAt: iso(b.createdAt) },
      refundWillBeRecorded: !!b.paymentId,
    });
  });

  const cancelConfirm = guard(async (id, body) => {
    const tok = verifyToken(body.confirmToken, secret, now());
    if (!tok || tok.t !== 'cancel' || tok.s !== id.subject || !validId(tok.b)) return R(400, { error: 'invalid_or_expired_confirmation' });
    const bid = tok.b;
    const reason = cleanText(body.reason, 200) || 'Cancelled via AI assistant';
    const bRef = bookingsCol().doc(bid);
    const rRef = refundsCol().doc(bid);

    const out = await db.runTransaction(async (tx) => {
      const bs = await tx.get(bRef);
      const rs = await tx.get(rRef);
      if (!bs.exists) return { err: R(404, { error: 'booking_not_found' }) };
      const b = bs.data();
      if (!strictOwner(id, b)) return { err: R(404, { error: 'booking_not_found' }) };
      if (lower(b.status) !== 'pending') return { err: R(409, { error: 'not_eligible', status: lower(b.status) }) };
      tx.update(bRef, { status: 'cancelled', cancellationReason: reason, cancelledVia: 'ai_assistant', cancelledAt: serverTimestamp() });
      let created = false;
      if (b.paymentId && !rs.exists) {
        // Same shape the existing app writes, so the existing refund UI keeps working.
        tx.set(rRef, {
          bookingId: bid, userId: b.userId || '', partnerId: b.partnerId || '',
          amount: b.amount || 0, refundAmount: 0, reason,
          status: 'pending', message: 'Your refund is being processed.',
          requestedAt: serverTimestamp(), processedAt: null,
          paymentId: b.paymentId, refundId: '',
        });
        created = true;
      }
      return { ok: true, hadPayment: !!b.paymentId, created };
    });
    if (out.err) return out.err;

    let trigger = 'skipped';
    if (out.created) {
      try { trigger = (await triggerRefund(bid)) ? 'ok' : 'failed'; } catch (e) { trigger = 'failed'; }
    }
    let refundStatus = null;
    if (out.hadPayment) {
      const rs = await refundsCol().doc(bid).get();          // report the REAL stored status
      refundStatus = rs.exists ? lower(rs.data().status || 'pending') : null;
    }
    return R(200, { cancelled: true, bookingId: bid, refund: { recorded: out.hadPayment, status: refundStatus, trigger } });
  });

  // ---------- 4) complaints ----------
  const isOpen = (c) => !['resolved', 'closed'].includes(lower(c.status));

  const complaint = guard(async (id, body) => {
    const type = COMPLAINT_TYPES.includes(body.type) ? body.type : null;
    const description = cleanText(body.description, 1000);
    if (!type || description.length < 5) return R(400, { error: 'invalid_complaint' });
    let bookingId = '';
    if (body.bookingId) {
      if (!(await getOwnedBooking(id, body.bookingId, false))) return R(404, { error: 'booking_not_found' });
      bookingId = body.bookingId;
    }
    const dedupeKey = crypto.createHash('sha256').update([id.subject, bookingId || 'general', type].join('|')).digest('hex').slice(0, 32);

    const out = await db.runTransaction(async (tx) => {
      const existing = await tx.get(complaintsCol().where('dedupeKey', '==', dedupeKey));
      const open = existing.docs.map((d) => d.data()).find(isOpen);
      if (open) return { duplicate: true, ticketNo: String(open.ticketNo), status: open.status };
      let ticketNo = null;
      for (let i = 0; i < 8 && !ticketNo; i++) {
        const cand = randomTicket();
        const clash = await tx.get(complaintsCol().where('ticketNo', '==', cand));
        if (clash.empty) ticketNo = cand;
      }
      if (!ticketNo) throw new Error('ticket_generation_failed');
      tx.set(complaintsCol().doc(), {
        ticketNo, bookingId, type, description,
        userId: id.uid || ('91' + id.phone10),     // same value the existing Complaints tab queries by
        phone: id.phone10 ? '91' + id.phone10 : '',
        email: id.email || '',
        status: 'Pending', createdAt: serverTimestamp(),
        source: 'ai_assistant', dedupeKey,
      });
      return { duplicate: false, ticketNo, status: 'Pending' };
    });
    return R(200, out);
  });

  const complaintsMine = guard(async (id, body) => {
    const found = new Map();
    const add = (snap) => snap.docs.forEach((d) => found.set(d.id, d.data()));
    add(await complaintsCol().where('userId', 'in', [...id.ids]).get());
    if (id.phone10) add(await complaintsCol().where('phone', 'in', [id.phone10, '91' + id.phone10]).get());
    if (id.email) add(await complaintsCol().where('email', '==', id.email).get());
    let list = [...found.entries()].map(([cid, c]) => ({
      id: cid, ticketNo: c.ticketNo ? String(c.ticketNo) : null, type: c.type || '', status: c.status || 'Under Review',
      bookingId: c.bookingId || '', createdAt: iso(c.createdAt),
    }));
    const want = cleanText(body.ticketNo, 20).replace(/^#/, '');
    if (want) list = list.filter((c) => c.ticketNo === want);
    list.sort((x, y) => String(y.createdAt || '').localeCompare(String(x.createdAt || '')));
    return R(200, { tickets: list.slice(0, 20) });
  });

  // ---------- 5) admin: AI complaints ----------
  async function adminAiComplaints(headers) {
    const d = await verifyBearer(headers);
    if (!isGoogle(d)) return R(401, { error: 'unauthorized' });
    if (!adminEmails.includes(lower(d.email))) return R(403, { error: 'forbidden' });
    const snap = await complaintsCol().where('source', '==', 'ai_assistant').get();
    const rows = snap.docs.map((x) => ({ id: x.id, ...x.data() }));
    rows.sort((a, b) => String((iso(b.createdAt)) || '').localeCompare(String(iso(a.createdAt) || '')));
    const top = rows.slice(0, 200);
    const bookingIds = [...new Set(top.map((r) => r.bookingId).filter(validId))];
    const info = {};
    await Promise.all(bookingIds.map(async (bid) => {
      const s = await bookingsCol().doc(bid).get();
      if (s.exists) info[bid] = { customerName: s.data().customerName || '', service: s.data().service || '' };
    }));
    return R(200, {
      complaints: top.map((r) => ({
        id: r.id, ticketNo: r.ticketNo ? String(r.ticketNo) : null, type: r.type || '', description: r.description || '',
        status: r.status || '', bookingId: r.bookingId || '', createdAt: iso(r.createdAt),
        userId: r.userId || '', phone: r.phone || '', email: r.email || '',
        customerName: (info[r.bookingId] || {}).customerName || '', service: (info[r.bookingId] || {}).service || '',
      })),
    });
  }

  const STATUSES = ['Pending', 'In Progress', 'Resolved', 'Closed'];
  async function adminSetStatus(headers, body) {
    const d = await verifyBearer(headers);
    if (!isGoogle(d)) return R(401, { error: 'unauthorized' });
    if (!adminEmails.includes(lower(d.email))) return R(403, { error: 'forbidden' });
    if (!STATUSES.includes(body.status) || !validId(body.id)) return R(400, { error: 'invalid_request' });
    const ref = complaintsCol().doc(body.id);
    const snap = await ref.get();
    if (!snap.exists || snap.data().source !== 'ai_assistant') return R(404, { error: 'not_found' });
    await ref.update({ status: body.status, updatedAt: serverTimestamp(), updatedBy: lower(d.email) });
    return R(200, { ok: true, status: body.status });
  }

  return { identify, bookings, refund, cancelPrepare, cancelConfirm, complaint, complaintsMine, adminAiComplaints, adminSetStatus };
}

// ---------- wiring for index.js ----------
function buildFromEnv({ db, auth, env = process.env }) {
  const { FieldValue } = require('firebase-admin/firestore');
  const triggerRefund = async (bookingId) => {
    if (!env.REFUND_API_URL) return false;
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), 10000);
    try {
      const r = await fetch(env.REFUND_API_URL, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ bookingId }), signal: ctl.signal,
      });
      return r.ok;
    } finally { clearTimeout(timer); }
  };
  return createSupport({
    db, auth,
    secret: env.SESSION_SECRET,
    adminEmails: String(env.ADMIN_EMAILS || '').split(',').map(lower).filter(Boolean),
    overdueHours: Number(env.REFUND_OVERDUE_HOURS) > 0 ? Number(env.REFUND_OVERDUE_HOURS) : 48,
    triggerRefund,
    serverTimestamp: () => FieldValue.serverTimestamp(),
  });
}

function createRouter(support, express) {
  const router = express.Router();
  let limiter = (req, res, next) => next();
  try {
    const rateLimit = require('express-rate-limit');
    limiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false });
  } catch (e) { /* express-rate-limit not installed: skip */ }
  const wrap = (fn) => async (req, res) => {
    try {
      const r = await fn(req.headers, req.body || {});
      res.status(r.status).json(r.body);
    } catch (e) {
      console.error('SUPPORT ERROR:', e && e.message);
      res.status(500).json({ error: 'internal' });
    }
  };
  router.use('/support', limiter);
  router.post('/support/bookings', wrap(support.bookings));
  router.post('/support/refund', wrap(support.refund));
  router.post('/support/cancel/prepare', wrap(support.cancelPrepare));
  router.post('/support/cancel/confirm', wrap(support.cancelConfirm));
  router.post('/support/complaint', wrap(support.complaint));
  router.post('/support/complaints/mine', wrap(support.complaintsMine));
  router.get('/support/admin/ai-complaints', wrap((h) => support.adminAiComplaints(h)));
  router.post('/support/admin/complaint-status', wrap(support.adminSetStatus));
  return router;
}

module.exports = { createSupport, createRouter, buildFromEnv, signSession, signToken, verifyToken, COMPLAINT_TYPES };
