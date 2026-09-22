require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore } = require('firebase-admin/firestore');

// Load Firebase service account from an environment variable instead of a
// local JSON file (the file is never pushed to GitHub for security reasons).
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

initializeApp({ credential: cert(serviceAccount) });
const db = getFirestore(); // kept in case you need it elsewhere; not written to here

const app = express();
app.use(cors());
app.use(express.json());

const FAST2SMS_API_KEY = process.env.FAST2SMS_API_KEY;
const FAST2SMS_URL = 'https://www.fast2sms.com/dev/bulkV2';

// In-memory OTP store. Key = phone exactly as frontend sends it (e.g. "919106820129")
const otpStore = {};

// ---------- Step 1: Send OTP ----------
app.post('/send-otp', async (req, res) => {
  const { phone } = req.body; // e.g. "919106820129" (91 + 10 digit, from getFullPhone())

  if (!phone || phone.length < 10) {
    return res.status(400).json({ success: false, message: 'Valid phone number required' });
  }

  const smsNumber = phone.slice(-10); // Fast2SMS ne 10 digit j joie, country code vagar
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  try {
    const response = await axios.post(
      FAST2SMS_URL,
      {
        route: 'q', // Quick Transactional route - no DLT required
        message: `Your VoltMaster OTP is ${otp}. Do not share this with anyone.`,
        language: 'english',
        flash: 0,
        numbers: smsNumber,
      },
      {
        headers: {
          authorization: FAST2SMS_API_KEY,
          'Content-Type': 'application/json',
        },
      }
    );

    if (response.data.return === true) {
      otpStore[phone] = { otp, expiresAt: Date.now() + 5 * 60 * 1000 }; // 5 min expiry
      res.json({ success: true, message: 'OTP sent successfully' });
    } else {
      console.error('FAST2SMS REJECTED:', JSON.stringify(response.data));
      res.status(500).json({ success: false, message: 'Failed to send OTP', error: response.data });
    }
  } catch (err) {
    console.error('SEND-OTP ERROR:', err.response?.data || err.message);
    res.status(500).json({ success: false, error: err.response?.data || err.message });
  }
});

// ---------- Step 2: Verify OTP ----------
app.post('/verify-otp', (req, res) => {
  const { phone, otp } = req.body;
  const record = otpStore[phone];

  if (!record) {
    return res.status(400).json({ success: false, message: 'No OTP found, please request a new one' });
  }
  if (Date.now() > record.expiresAt) {
    delete otpStore[phone];
    return res.status(400).json({ success: false, message: 'OTP expired' });
  }
  if (record.otp !== otp) {
    return res.status(400).json({ success: false, message: 'Invalid OTP' });
  }

  delete otpStore[phone];
  res.json({ success: true });
});

app.listen(process.env.PORT || 3000, () => console.log('Server chalu chhe'));
