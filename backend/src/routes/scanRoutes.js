import express from 'express';
import multer from 'multer';
import { scanUrl, scanEmail, scanMessage, scanQrContent } from '../services/trustshield/index.js';
import { decodeQrBuffer } from '../services/trustshield/qrDecode.js';
import { makeSignal } from '../services/trustshield/utils.js';
import { buildResult } from '../services/trustshield/riskEngine.js';
import * as repo from '../repositories/scanRepository.js';

const router = express.Router();

const MAX_URL_LEN = 2048;
const MAX_CONTENT_LEN = 20000;

// QR uploads: memory storage, 2MB cap, images only. Untrusted input.
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, cb) => {
    if (/^image\//.test(file.mimetype)) cb(null, true);
    else cb(Object.assign(new Error('Only image files are allowed for QR scanning.'), { status: 400 }));
  }
});

function badRequest(res, message) {
  return res.status(400).json({ error: message });
}

// Persist and respond, so the same shape is returned across all scanners.
async function persistAndSend(res, inputType, preview, result) {
  const saved = await repo.saveScan({ inputType, inputPreview: preview, result });
  return res.status(201).json({ id: saved.id, createdAt: saved.createdAt, ...result });
}

// POST /api/scan/url
router.post('/scan/url', async (req, res, next) => {
  try {
    const { url } = req.body || {};
    if (typeof url !== 'string' || !url.trim()) return badRequest(res, 'A "url" string is required.');
    if (url.length > MAX_URL_LEN) return badRequest(res, `URL exceeds ${MAX_URL_LEN} characters.`);
    const { result, preview } = scanUrl(url);
    return persistAndSend(res, 'url', preview, result);
  } catch (err) {
    if (err.status === 400) return badRequest(res, err.message);
    next(err);
  }
});

// POST /api/scan/email
router.post('/scan/email', async (req, res, next) => {
  try {
    const { sender, subject, content } = req.body || {};
    if ((!content || !String(content).trim()) && (!subject || !String(subject).trim())) {
      return badRequest(res, 'Email "content" (or at least a "subject") is required.');
    }
    if ((content || '').length > MAX_CONTENT_LEN) return badRequest(res, `Content exceeds ${MAX_CONTENT_LEN} characters.`);
    const { result, preview } = scanEmail({ sender, subject, content });
    return persistAndSend(res, 'email', preview, result);
  } catch (err) { next(err); }
});

// POST /api/scan/message
router.post('/scan/message', async (req, res, next) => {
  try {
    const { content, message, text, sender } = req.body || {};
    const body = content || message || text;
    if (typeof body !== 'string' || !body.trim()) return badRequest(res, 'A "content" string is required.');
    if (body.length > MAX_CONTENT_LEN) return badRequest(res, `Content exceeds ${MAX_CONTENT_LEN} characters.`);
    const { result, preview } = scanMessage({ content: body, sender });
    return persistAndSend(res, 'message', preview, result);
  } catch (err) { next(err); }
});

// POST /api/scan/qr  (multipart: field "image", or JSON { content })
router.post('/scan/qr', (req, res, next) => {
  upload.single('image')(req, res, async (uploadErr) => {
    try {
      if (uploadErr) return badRequest(res, uploadErr.message);
      let decoded = null;
      if (req.file) {
        decoded = await decodeQrBuffer(req.file.buffer);
        if (!decoded) {
          const result = buildResult('qr', [makeSignal('QR_UNDECODABLE')]);
          return persistAndSend(res, 'qr', null, result);
        }
      } else if (req.body && typeof req.body.content === 'string' && req.body.content.trim()) {
        decoded = req.body.content.trim();
      } else {
        return badRequest(res, 'Provide a QR image file (field "image") or decoded "content".');
      }
      const { result, preview, decoded: dest } = scanQrContent(decoded);
      const saved = await repo.saveScan({ inputType: 'qr', inputPreview: preview, result });
      return res.status(201).json({ id: saved.id, createdAt: saved.createdAt, decodedDestination: dest, ...result });
    } catch (err) { next(err); }
  });
});

// GET /api/scans
router.get('/scans', async (req, res, next) => {
  try {
    const limit = Math.max(1, Math.min(200, parseInt(req.query.limit, 10) || 50));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    return res.json(await repo.listScans(limit, offset));
  } catch (err) { next(err); }
});

// GET /api/scans/:id
router.get('/scans/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return badRequest(res, 'Invalid scan id.');
    const scan = await repo.getScanById(id);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });
    return res.json(scan);
  } catch (err) { next(err); }
});

// DELETE /api/scans/:id
router.delete('/scans/:id', async (req, res, next) => {
  try {
    const id = parseInt(req.params.id, 10);
    if (!Number.isInteger(id)) return badRequest(res, 'Invalid scan id.');
    const ok = await repo.deleteScan(id);
    if (!ok) return res.status(404).json({ error: 'Scan not found.' });
    return res.status(204).send();
  } catch (err) { next(err); }
});

// GET /api/dashboard
router.get('/dashboard', async (req, res, next) => {
  try {
    return res.json(await repo.getDashboard());
  } catch (err) { next(err); }
});

export default router;
