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

// Partner document upload -> private GitHub repo (see partnerUploadRoutes.js)
app.set("trust proxy", 1);
app.use(require("./partnerUploadRoutes"));

// ---------- Fast2SMS Smart OTP (WhatsApp first, SMS fallback) ----------
// Render Environment ma aa 2 joiye:
//   FAST2SMS_API_KEY  = tamari API key
//   FAST2SMS_OTP_ID   = Fast2SMS panel > Smart OTP mathi malelo OTP ID
const FAST2SMS_API_KEY = process.env.FAST2SMS_API_KEY;
const FAST2SMS_OTP_ID = process.env.FAST2SMS_OTP_ID;
const FAST2SMS_OTP_SEND_URL = 'https://www.fast2sms.com/dev/otp/send';
const FAST2SMS_OTP_VERIFY_URL = 'https://www.fast2sms.com/dev/otp/verify';

// Ek number par 30 sec ma ek j OTP (spam / paisa no waste rokva)
const lastSent = {};
const COOLDOWN_MS = 30 * 1000;

const f2sHeaders = {
  authorization: FAST2SMS_API_KEY,
  'Content-Type': 'application/json',
};

// ---------- Step 1: Send OTP ----------
app.post('/send-otp', async (req, res) => {
  const { phone } = req.body; // e.g. "919106820129" (91 + 10 digit, from getFullPhone())

  if (!phone || phone.length < 10) {
    return res.status(400).json({ success: false, message: 'Valid phone number required' });
  }

  const smsNumber = phone.slice(-10); // Fast2SMS ne 10 digit j joie, country code vagar

  if (!/^[6-9]\d{9}$/.test(smsNumber)) {
    return res.status(400).json({ success: false, message: 'Invalid mobile number' });
  }

  if (Date.now() - (lastSent[smsNumber] || 0) < COOLDOWN_MS) {
    return res.status(429).json({ success: false, message: 'Please wait 30 seconds and try again' });
  }

  try {
    // Fast2SMS pote OTP banave chhe, WhatsApp par moklse, fail thay to SMS par
    const response = await axios.post(
      FAST2SMS_OTP_SEND_URL,
      { otp_id: FAST2SMS_OTP_ID, mobile: smsNumber },
      { headers: f2sHeaders }
    );

    if (response.data.return === true) {
      lastSent[smsNumber] = Date.now();
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
app.post('/verify-otp', async (req, res) => {
  const { phone, otp } = req.body;

  if (!phone || phone.length < 10 || !otp) {
    return res.status(400).json({ success: false, message: 'Phone and OTP required' });
  }

  const smsNumber = phone.slice(-10);

  try {
    const response = await axios.post(
      FAST2SMS_OTP_VERIFY_URL,
      { mobile: smsNumber, otp: String(otp) },
      { headers: f2sHeaders }
    );

    if (response.data.return === true) {
      return res.json({ success: true });
    }
    return res.status(400).json({ success: false, message: response.data.message || 'Invalid OTP' });
  } catch (err) {
    // Fast2SMS wrong OTP par 400, vaparelo OTP par 404 aape chhe
    const status = err.response?.status;
    if (status === 400 || status === 404) {
      return res.status(400).json({
        success: false,
        message: err.response?.data?.message || 'Invalid OTP',
      });
    }
    console.error('VERIFY-OTP ERROR:', err.response?.data || err.message);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

app.listen(process.env.PORT || 3000, () => console.log('Server chalu chhe'));
