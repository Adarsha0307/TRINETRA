import express from 'express';
import rateLimit from 'express-rate-limit';
import { enqueueJob, requestCancel } from '../services/sandbox/jobManager.js';
import { getJob, deleteJob, listRecent } from '../services/sandbox/jobStore.js';
import { sandboxConfig } from '../services/sandbox/config.js';
import { UrlValidationError } from '../services/sandbox/urlNormalize.js';
import { SsrfError } from '../services/sandbox/ssrf.js';

const router = express.Router();

// Stricter limiter for job creation (browser analysis is expensive).
const createLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.SANDBOX_CREATE_RATE_LIMIT) || 10,
  standardHeaders: true, legacyHeaders: false,
  message: { error: 'Too many sandbox jobs. Please wait a minute and try again.' },
});

function publicJob(job) {
  if (!job) return null;
  return {
    id: job.id, status: job.status, host: job.host,
    riskScore: job.riskScore ?? null, riskLevel: job.riskLevel ?? null,
    confidence: job.confidence ?? null, dynamicPerformed: job.dynamicPerformed,
    error: job.error ?? null, createdAt: job.createdAt, expiresAt: job.expiresAt,
    isolationMode: sandboxConfig.isolationMode,
  };
}

// POST /api/sandbox/jobs  — create an async analysis job (returns immediately).
router.post('/jobs', createLimiter, async (req, res, next) => {
  try {
    const { url } = req.body || {};
    if (typeof url !== 'string' || !url.trim()) return res.status(400).json({ error: 'A "url" string is required.' });
    const { id, status } = await enqueueJob(url);
    return res.status(202).json({
      id, status,
      pollUrl: `/api/sandbox/jobs/${id}`,
      reportUrl: `/api/sandbox/jobs/${id}/report`,
      isolationMode: sandboxConfig.isolationMode,
      notice: 'Development / reduced-isolation mode. Process separation is not equivalent to container isolation.',
    });
  } catch (err) {
    if (err instanceof UrlValidationError || err instanceof SsrfError) return res.status(400).json({ error: err.message, code: err.code });
    next(err);
  }
});

// GET /api/sandbox/jobs  — recent jobs (summary).
router.get('/jobs', async (req, res, next) => {
  try { return res.json(await listRecent(Number(req.query.limit) || 20)); }
  catch (err) { next(err); }
});

// GET /api/sandbox/jobs/:jobId  — job status.
router.get('/jobs/:jobId', async (req, res, next) => {
  try {
    const job = await getJob(req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    return res.json(publicJob(job));
  } catch (err) { next(err); }
});

// GET /api/sandbox/jobs/:jobId/report  — full explainable report.
router.get('/jobs/:jobId/report', async (req, res, next) => {
  try {
    const job = await getJob(req.params.jobId);
    if (!job) return res.status(404).json({ error: 'Job not found.' });
    if (job.status === 'expired') return res.status(410).json({ error: 'Report has expired and was purged.' });
    if (job.status !== 'completed') return res.status(409).json({ error: `Report not ready (status: ${job.status}).`, status: job.status });
    return res.json({ id: job.id, status: job.status, ...job.report });
  } catch (err) { next(err); }
});

// GET /api/sandbox/jobs/:jobId/screenshot  — temporary artifact (if present).
router.get('/jobs/:jobId/screenshot', async (req, res, next) => {
  try {
    const job = await getJob(req.params.jobId);
    if (!job || !job.screenshotPath || job.status === 'expired') return res.status(404).json({ error: 'No screenshot available.' });
    return res.sendFile(job.screenshotPath, err => { if (err) res.status(404).json({ error: 'Screenshot missing.' }); });
  } catch (err) { next(err); }
});

// DELETE /api/sandbox/jobs/:jobId  — cancel/delete a job + artifacts.
router.delete('/jobs/:jobId', async (req, res, next) => {
  try {
    requestCancel(req.params.jobId);
    const ok = await deleteJob(req.params.jobId);
    if (!ok) return res.status(404).json({ error: 'Job not found.' });
    return res.status(204).send();
  } catch (err) { next(err); }
});

export default router;
