// jobPhotoRoutes.js
// POST /job-photos  -> partner service SHARU karta pehla na photos (indoor/outdoor/serial) GitHub ma save kare
//                      ane job ne 'accepted' mathi 'working' kari de. (OTP kaam purun thaya pachhi, app ma)
//
// index.js ma: app.use(require('./jobPhotoRoutes'));  (express.json() pehla mukvu)
//
// Render env vars (partner upload mate pehla thi chhe j): GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO

const express = require('express');
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

  return router;
})();
