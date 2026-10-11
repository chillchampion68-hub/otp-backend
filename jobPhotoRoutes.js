// jobPhotoRoutes.js
// POST /job-photos  -> partner service SHARU karta pehla na photos (indoor/outdoor/serial) GitHub ma save kare
//                      ane job ne 'accepted' mathi 'working' kari de. (OTP kaam purun thaya pachhi, app ma)
//
// index.js ma: app.use(require('./jobPhotoRoutes'));  (express.json() pehla mukvu)
//
// Render env vars (partner upload mate pehla thi chhe j): GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO

const express = require('express');
const crypto = require('crypto');
const { getAuth } = require('firebase-admin/auth');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');

const ALLOWED_KEYS = new Set(['indoor', 'outdoor', 'serial', 'item', 'work']);

module.exports = (function () {
  const router = express.Router();
  // photos base64 ma aave chhe, etle ya fakt aa route mate moti limit
  const bigJson = express.json({ limit: '15mb' });

  async function githubPut(path, base64Content, message) {
    const { GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO } = process.env;
    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
    const headers = {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: 'application/vnd.github+json',
      'Content-Type': 'application/json',
      'User-Agent': 'voltmaster-backend'
    };

    // file pehla thi hoy to overwrite mate sha joiye
    let sha;
    const existing = await fetch(url, { headers });
    if (existing.ok) sha = (await existing.json()).sha;

    const res = await fetch(url, {
      method: 'PUT',
      headers,
      body: JSON.stringify({ message, content: base64Content, ...(sha ? { sha } : {}) })
    });
    if (!res.ok) {
      const t = await res.text();
      throw new Error(`GitHub save failed (${res.status}): ${t.slice(0, 200)}`);
    }
  }

  router.post('/job-photos', bigJson, async (req, res) => {
    try {
      // 1) Firebase login check
      const authHeader = req.headers.authorization || '';
      const idToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (!idToken) return res.status(401).json({ ok: false, error: 'Login token nathi.' });

      let uid;
      try {
        uid = (await getAuth().verifyIdToken(idToken)).uid;
      } catch (e) {
        return res.status(401).json({ ok: false, error: 'Login session invalid chhe.' });
      }

      // 2) input check
      const { jobId, photos } = req.body || {};
      if (!jobId || typeof jobId !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(jobId)) {
        return res.status(400).json({ ok: false, error: 'Job ID galat chhe.' });
      }
      if (!Array.isArray(photos) || photos.length === 0 || photos.length > 5) {
        return res.status(400).json({ ok: false, error: 'Photos jaruri chhe.' });
      }

      // 3) job aa partner nu j chhe ane "working" chhe te check
      const jobRef = getFirestore().collection('serviceRequests').doc(jobId);
      const jobSnap = await jobRef.get();
      if (!jobSnap.exists) return res.status(404).json({ ok: false, error: 'Job malyo nahi.' });
      const job = jobSnap.data();
      if (job.partnerId !== uid) return res.status(403).json({ ok: false, error: 'Aa job tamaro nathi.' });
      if (job.status !== 'accepted') {
        return res.status(400).json({ ok: false, error: 'Aa job ma photos pehla thi upload thai gaya chhe ke job accepted nathi.' });
      }

      // 4) badha photo GitHub ma save
      const files = {};
      const stamp = Date.now();
      for (const p of photos) {
        if (!p || !ALLOWED_KEYS.has(p.key)) {
          return res.status(400).json({ ok: false, error: 'Photo type galat chhe.' });
        }
        const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(p.data || '');
        if (!m) return res.status(400).json({ ok: false, error: 'Photo format galat chhe.' });
        if (m[1].length > 4 * 1024 * 1024) {
          return res.status(400).json({ ok: false, error: 'Photo bahu moto chhe.' });
        }
        const path = `job-photos/${jobId}/${p.key}-${stamp}.jpg`;
        await githubPut(path, m[1], `Job ${jobId}: ${p.key} photo`);
        files[p.key] = path;
      }

      // 5) job doc ma photo path save + status 'working' (OTP have kaam purun thaya pachhi lagshe)
      await jobRef.update({
        status: 'working',
        startedAt: FieldValue.serverTimestamp(),
        servicePhotos: {
          files,
          uploadedBy: uid,
          uploadedAt: FieldValue.serverTimestamp()
        }
      });

      return res.json({ ok: true, files });
    } catch (e) {
      console.error('job-photos error:', e);
      return res.status(500).json({ ok: false, error: 'Server error: ' + e.message });
    }
  });

  // ---------------------------------------------------------------
  // POST /admin-job-photos  { jobId, adminId }
  // Admin page photos jova mate. Admin ID admin_config/settings.adminCode sathe check thay chhe
  // (admin page ma je check chhe e j). Photos private GitHub repo mathi aavi ne base64 ma pacha jay.
  // ---------------------------------------------------------------
  const smallJson = express.json({ limit: '10kb' });

  function sameText(a, b) {
    const x = Buffer.from(String(a));
    const y = Buffer.from(String(b));
    return x.length === y.length && crypto.timingSafeEqual(x, y);
  }

  async function githubGetRaw(path) {
    const { GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO } = process.env;
    const url = `https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}`;
    const r = await fetch(url, {
      headers: {
        Authorization: `Bearer ${GITHUB_TOKEN}`,
        Accept: 'application/vnd.github.raw',
        'User-Agent': 'voltmaster-backend'
      }
    });
    if (!r.ok) throw new Error(`GitHub read failed (${r.status})`);
    return Buffer.from(await r.arrayBuffer());
  }

  router.post('/admin-job-photos', smallJson, async (req, res) => {
    try {
      const { jobId, adminId } = req.body || {};
      if (!adminId || typeof adminId !== 'string' || adminId.length !== 10) {
        return res.status(401).json({ ok: false, error: 'Admin ID galat chhe.' });
      }
      if (!jobId || typeof jobId !== 'string' || !/^[A-Za-z0-9_-]{1,100}$/.test(jobId)) {
        return res.status(400).json({ ok: false, error: 'Job ID galat chhe.' });
      }

      const cfg = await getFirestore().collection('admin_config').doc('settings').get();
      if (!cfg.exists || !cfg.data().adminCode || !sameText(cfg.data().adminCode, adminId)) {
        return res.status(403).json({ ok: false, error: 'Admin ID galat chhe.' });
      }

      const jobSnap = await getFirestore().collection('serviceRequests').doc(jobId).get();
      if (!jobSnap.exists) return res.status(404).json({ ok: false, error: 'Job malyo nahi.' });
      const files = jobSnap.data().servicePhotos && jobSnap.data().servicePhotos.files;
      if (!files || Object.keys(files).length === 0) {
        return res.status(404).json({ ok: false, error: 'Aa job ma service photos nathi.' });
      }

      const photos = [];
      for (const [key, path] of Object.entries(files)) {
        // fakt aa j job na folder ni file j vanchay
        if (typeof path !== 'string' || !path.startsWith(`job-photos/${jobId}/`) || path.includes('..')) continue;
        const buf = await githubGetRaw(path);
        photos.push({ key, data: 'data:image/jpeg;base64,' + buf.toString('base64') });
      }
      if (photos.length === 0) return res.status(404).json({ ok: false, error: 'Photos malya nahi.' });

      return res.json({ ok: true, photos });
    } catch (e) {
      console.error('admin-job-photos error:', e);
      return res.status(500).json({ ok: false, error: 'Server error: ' + e.message });
    }
  });

  return router;
})();
