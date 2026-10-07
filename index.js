// =====================================================
// VoltMaster OTP backend  -  Fast2SMS Smart OTP
// WhatsApp first, SMS fallback (fallback is set in Fast2SMS panel)
// Routes used by login.html:  POST /send-otp   POST /verify-otp
//
// Render ma Environment Variables set karo:
//   FAST2SMS_API_KEY = tamari Fast2SMS API key (Dev API section)
//   FAST2SMS_OTP_ID  = Smart OTP panel mathi malelo OTP ID
//
// package.json ma: "dependencies": { "express": "^4", "cors": "^2" }
// Node 18+ joiye (fetch built-in chhe)
// =====================================================
const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());            // production ma: cors({ origin: "https://tamaro-domain.com" })
app.use(express.json());

const API_KEY = process.env.FAST2SMS_API_KEY;
const OTP_ID = process.env.FAST2SMS_OTP_ID;

// Page "91XXXXXXXXXX" moklse, Fast2SMS ne 10 digit joiye
function toTenDigits(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  const ten = digits.length === 12 && digits.startsWith("91") ? digits.slice(2) : digits;
  return /^[6-9]\d{9}$/.test(ten) ? ten : null;
}

// Simple abuse protection (paisa bachava): ek number par 30 sec ma 1 j OTP
const lastSent = new Map();
const COOLDOWN_MS = 30 * 1000;

async function f2s(path, body) {
  const res = await fetch("https://www.fast2sms.com/dev/otp/" + path, {
    method: "POST",
    headers: { Authorization: API_KEY, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch (e) {}
  return { status: res.status, data };
}

app.get("/", (req, res) => res.send("OTP backend running"));

// ---------- SEND OTP ----------
app.post("/send-otp", async (req, res) => {
  try {
    const mobile = toTenDigits(req.body.phone);
    if (!mobile) return res.status(400).json({ success: false, message: "Invalid phone" });

    const last = lastSent.get(mobile) || 0;
    if (Date.now() - last < COOLDOWN_MS) {
      return res.status(429).json({ success: false, message: "Please wait 30 seconds before retrying" });
    }

    const { data } = await f2s("send", { otp_id: OTP_ID, mobile });
    if (data.return === true) {
      lastSent.set(mobile, Date.now());
      return res.json({ success: true });
    }
    console.error("Fast2SMS send error:", data);
    return res.status(502).json({ success: false, message: data.message || "Send failed" });
  } catch (err) {
    console.error("send-otp error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ---------- VERIFY OTP ----------
app.post("/verify-otp", async (req, res) => {
  try {
    const mobile = toTenDigits(req.body.phone);
    const otp = String(req.body.otp || "").trim();
    if (!mobile || !/^\d{4,8}$/.test(otp)) {
      return res.status(400).json({ success: false, message: "Invalid input" });
    }

    const { data } = await f2s("verify", { mobile, otp });
    if (data.return === true) return res.json({ success: true });
    return res.status(400).json({ success: false, message: data.message || "Invalid OTP" });
  } catch (err) {
    console.error("verify-otp error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("OTP backend on port " + PORT));
