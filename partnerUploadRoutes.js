// Secure partner-document upload: browser/app -> this route -> private GitHub repo.
// Env vars (Render): GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO, optional GITHUB_BRANCH (default main),
// optional UPLOAD_PUBLIC_BASE_URL (default https://<request host>).
const express = require("express");
const multer = require("multer");
const cors = require("cors");
const crypto = require("crypto");
const rateLimit = require("express-rate-limit");

const router = express.Router();
const MB = 1024 * 1024;

// kind -> repo folder, filename suffix, size cap, allowed types (same as the existing forms)
const KINDS = {
  "profile":      { folder: "profile",      suffix: "profile",       max: 5 * MB, types: ["jpg", "png", "webp", "gif"] },
  "aadhar-front": { folder: "aadhar-front", suffix: "aadhar_front",  max: 5 * MB, types: ["jpg", "png", "webp", "gif"] },
  "aadhar-back":  { folder: "aadhar-back",  suffix: "aadhar_back",   max: 5 * MB, types: ["jpg", "png", "webp", "gif"] },
  "bank":         { folder: "bank",         suffix: "bank_document", max: 2 * MB, types: ["jpg", "png", "pdf"] },
};
const MIME = { jpg: "image/jpeg", png: "image/png", webp: "image/webp", gif: "image/gif", pdf: "application/pdf" };

function detectType(b) {
  if (b.length < 12) return null;
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "jpg";
  if (b.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "png";
  if (b.slice(0, 4).toString("latin1") === "GIF8") return "gif";
  if (b.slice(0, 4).toString("latin1") === "RIFF" && b.slice(8, 12).toString("latin1") === "WEBP") return "webp";
  if (b.slice(0, 4).toString("latin1") === "%PDF") return "pdf";
  return null;
}

function gh(path, options) {
  const { GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN } = process.env;
  return fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/contents/${path}${options.query || ""}`, {
    method: options.method || "GET",
    headers: {
      Authorization: `Bearer ${GITHUB_TOKEN}`,
      Accept: options.accept || "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "voltmaster-partner-upload",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
    },
    body: options.body,
  });
}

async function putToGitHub(path, buf) {
  const branch = process.env.GITHUB_BRANCH || "main";
  for (let attempt = 1; attempt <= 4; attempt++) {
    const r = await gh(path, {
      method: "PUT",
      body: JSON.stringify({ message: `Add ${path}`, content: buf.toString("base64"), branch }),
    });
    if (r.ok) return;
    // simultaneous uploads can briefly conflict on the branch: retry those and 5xx
    if ((r.status === 409 || r.status >= 500) && attempt < 4) {
      await new Promise((ok) => setTimeout(ok, 300 * attempt + Math.random() * 300));
      continue;
    }
    throw new Error(`GitHub PUT ${r.status}: ${(await r.text()).slice(0, 200)}`);
  }
}

const limiter = rateLimit({ windowMs: 60 * 60 * 1000, limit: 40, standardHeaders: true, legacyHeaders: false,
  message: { error: "Too many uploads from this network." } });

const receive = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * MB, files: 1 } }).single("file");
const receiveJson = (req, res, next) => receive(req, res, (err) => {
  if (!err) return next();
  const tooBig = err.code === "LIMIT_FILE_SIZE";
  res.status(tooBig ? 413 : 400).json({ error: tooBig ? "File is too large." : "Invalid upload." });
});

router.options("/upload-partner-file", cors());
router.post("/upload-partner-file", cors(), limiter, receiveJson, async (req, res) => {
  try {
    if (!process.env.GITHUB_TOKEN || !process.env.GITHUB_OWNER || !process.env.GITHUB_REPO) {
      console.error("partner upload: GitHub env vars missing");
      return res.status(500).json({ error: "Upload service is not available." });
    }
    const kind = KINDS[req.body && req.body.kind];
    if (!kind || !req.file) return res.status(400).json({ error: "Invalid upload." });
    if (req.file.size > kind.max) return res.status(413).json({ error: `File is too large. Maximum size is ${kind.max / MB}MB.` });

    const ext = detectType(req.file.buffer); // decided from file contents, not the client's file name
    if (!ext || !kind.types.includes(ext)) {
      return res.status(415).json({ error: `Unsupported file type. Allowed: ${kind.types.join(", ").toUpperCase()}.` });
    }

    const filename = `${crypto.randomBytes(16).toString("hex")}_${kind.suffix}.${ext}`;
    await putToGitHub(`partner-uploads/${kind.folder}/${filename}`, req.file.buffer);

    const base = process.env.UPLOAD_PUBLIC_BASE_URL || `https://${req.get("host")}`;
    res.json({ url: `${base}/partner-file/${kind.folder}/${filename}` });
  } catch (err) {
    console.error("partner upload failed:", err.message);
    res.status(502).json({ error: "Could not save the document." });
  }
});

// Serves a stored file from the private repo. The 128-bit random name in the URL is the access key.
router.get("/partner-file/:folder/:filename", cors(), async (req, res) => {
  const m = /^[a-f0-9]{32}_(profile|aadhar_front|aadhar_back|bank_document)\.(jpg|png|webp|gif|pdf)$/.exec(req.params.filename);
  const kind = m && Object.values(KINDS).find((k) => k.suffix === m[1]);
  if (!kind || kind.folder !== req.params.folder) return res.status(404).end();
  try {
    const r = await gh(`partner-uploads/${kind.folder}/${req.params.filename}`, {
      accept: "application/vnd.github.raw+json",
      query: `?ref=${encodeURIComponent(process.env.GITHUB_BRANCH || "main")}`,
    });
    if (!r.ok) return res.status(r.status === 404 ? 404 : 502).end();
    res.set({
      "Content-Type": MIME[m[2]],
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "private, max-age=3600",
      "Cross-Origin-Resource-Policy": "cross-origin",
    });
    res.send(Buffer.from(await r.arrayBuffer()));
  } catch (err) {
    console.error("partner file fetch failed:", err.message);
    res.status(502).end();
  }
});

module.exports = router;
