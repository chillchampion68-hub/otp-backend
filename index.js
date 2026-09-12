require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const { initializeApp, cert } = require('firebase-admin/app');
const { getFirestore, FieldValue } = require('firebase-admin/firestore');
const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT
  ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
  : require('./serviceAccountKey.json');

initializeApp({ credential: cert(serviceAccount) });
const db = getFirestore();

const app = express();
app.use(cors());
app.use(express.json());

const AUTHKEY = process.env.MSG91_AUTHKEY;

app.post('/verify-access-token', async (req, res) => {
  const { accessToken, phone } = req.body;
  try {
    const response = await axios.post(
      'https://control.msg91.com/api/v5/widget/verifyAccessToken',
      { authkey: AUTHKEY, 'access-token': accessToken }
    );

    if (response.data.type === 'success') {
      await db.collection('users').doc(phone).set({
        phone: phone,
        verifiedAt: FieldValue.serverTimestamp()
      });
      res.json({ success: true });
    } else {
      res.status(400).json({ success: false, message: 'Invalid token' });
    }
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.listen(3000, () => console.log('Server chalu chhe port 3000 par'));
