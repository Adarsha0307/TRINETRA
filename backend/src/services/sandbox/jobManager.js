import { fork } from 'child_process';
import path from 'path';
import crypto from 'crypto';
import fs from 'fs/promises';
import { fileURLToPath } from 'url';
import { sandboxConfig } from './config.js';
import { normalizeUrl, redactUrl, safeUrlLabel } from './urlNormalize.js';
import { assertDestinationAllowed, SsrfError } from './ssrf.js';
import { staticAnalyze } from './staticAnalysis.js';
import { buildReport } from './riskEngine.js';
import { sanitizeReport } from './reportSanitizer.js';
import * as store from './jobStore.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WORKER_PATH = path.join(__dirname, 'analyzeWorker.js');
const ARTIFACT_DIR = path.join(__dirname, '../../../.sandbox-artifacts');

// Minimal env for the worker — DO NOT leak DB creds / secrets / API keys.
const WORKER_ENV = {
  PATH: process.env.PATH, HOME: process.env.HOME,
  PLAYWRIGHT_BROWSERS_PATH: process.env.PLAYWRIGHT_BROWSERS_PATH || '',
  NODE_ENV: process.env.NODE_ENV || 'development',
};

let playwrightAvailable = null;
async function hasPlaywright() {
  if (playwrightAvailable !== null) return playwrightAvailable;
  try { await import('playwright'); playwrightAvailable = true; } catch { playwrightAvailable = false; }
  return playwrightAvailable;
}

// Decide whether live dynamic browsing is permitted for this URL.
function dynamicPermitted(normalizedUrl, host) {
  if (sandboxConfig.allowPublic) return true;
  if (sandboxConfig.allowlistHosts.includes(host)) return true;
  if (sandboxConfig.allowTestOrigins) {
    for (const origin of sandboxConfig.testOrigins) {
      if (origin && normalizedUrl.toLowerCase().startsWith(origin)) return true;
    }
  }
  return false;
}

// Bounded-concurrency in-memory queue. Each entry keeps the REAL normalized URL
// in memory only (DB stores the redacted form) and is processed disposably.
const queue = [];
const running = new Set();
const cancelled = new Set();

export async function enqueueJob(inputUrl) {
  const { normalized, original } = normalizeUrl(inputUrl);
  const host = new URL(normalized).hostname;
  const id = crypto.randomUUID();
  const correlationId = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + sandboxConfig.retentionMinutes * 60 * 1000).toISOString();

  await store.createJob({
    id,
    originalUrlRedacted: redactUrl(original),
    normalizedUrlRedacted: redactUrl(normalized),
    host, correlationId, expiresAt,
  });

  queue.push({ id, normalized, host, correlationId });
  setImmediate(pump);
  return { id, status: 'queued' };
}

export function requestCancel(id) { cancelled.add(id); }

function pump() {
  while (running.size < sandboxConfig.concurrency && queue.length) {
    const job = queue.shift();
    running.add(job.id);
    runJob(job).catch(() => {}).finally(() => { running.delete(job.id); setImmediate(pump); });
  }
}

async function runJob(job) {
  const log = (msg) => console.log(JSON.stringify({ lvl: 'info', mod: 'sandbox', cid: job.correlationId, jobId: job.id, msg, target: safeUrlLabel(job.normalized) }));
  if (cancelled.has(job.id)) { cancelled.delete(job.id); return; }

  try {
    // 1) validating — SSRF / network policy (skipped only for permitted test origins).
    await store.setStatus(job.id, 'validating');
    log('validating');
    const isTestOrigin = sandboxConfig.allowTestOrigins &&
      sandboxConfig.testOrigins.some(o => o && job.normalized.toLowerCase().startsWith(o));
    if (!isTestOrigin) await assertDestinationAllowed(job.normalized);

    // 2) analyzing — static always; dynamic only if permitted + available.
    await store.setStatus(job.id, 'analyzing');
    log('analyzing');
    const stat = await staticAnalyze(job.normalized);

    let evidence = {
      analysisVersion: sandboxConfig.analysisVersion,
      isolationMode: sandboxConfig.isolationMode,
      normalizedUrl: redactUrl(job.normalized),
      hostname: stat.hostname,
      urlSignals: stat.urlSignals,
      lookalikeBrand: stat.lookalikeBrand,
      safeBrowsing: stat.safeBrowsing,
      dynamicPerformed: false,
      workerStatus: 'static-only',
    };

    const permitted = dynamicPermitted(job.normalized, job.host);
    const pw = permitted && await hasPlaywright();
    if (permitted && pw && !cancelled.has(job.id)) {
      await fs.mkdir(ARTIFACT_DIR, { recursive: true }).catch(() => {});
      const screenshotPath = path.join(ARTIFACT_DIR, `${job.id}.jpg`);
      const dyn = await runWorker(job, screenshotPath, isTestOrigin ? [job.host] : []);
      evidence = {
        ...evidence, ...dyn,
        normalizedUrl: redactUrl(job.normalized), // keep redacted for storage
        dynamicPerformed: dyn.workerStatus !== 'failed',
        workerStatus: dyn.workerStatus,
      };
    }

    const report = sanitizeReport(buildReport(evidence));
    await store.completeJob(job.id, {
      report,
      riskScore: report.riskScore,
      riskLevel: report.riskLevel,
      confidence: report.confidence,
      dynamicPerformed: report.observed.dynamicPerformed,
      screenshotPath: evidence.screenshotPath || null,
    });
    log(`completed level=${report.riskLevel} score=${report.riskScore}`);
  } catch (err) {
    const reason = err instanceof SsrfError ? `Blocked: ${err.message}` : `Analysis error: ${err.message}`;
    await store.setStatus(job.id, 'failed', reason);
    console.log(JSON.stringify({ lvl: 'warn', mod: 'sandbox', cid: job.correlationId, jobId: job.id, msg: 'failed', reason }));
  }
}

// Fork the disposable worker with a hard timeout; kill on timeout/cancel.
function runWorker(job, screenshotPath, allowHosts = []) {
  return new Promise((resolve) => {
    const child = fork(WORKER_PATH, [], { env: WORKER_ENV, silent: false });
    let done = false;
    const finish = (val) => { if (!done) { done = true; try { child.kill('SIGKILL'); } catch {} resolve(val); } };
    const timer = setTimeout(() => finish({ workerStatus: 'failed', errors: ['job timeout'], durationMs: sandboxConfig.jobTimeoutMs }), sandboxConfig.jobTimeoutMs);
    const cancelWatch = setInterval(() => { if (cancelled.has(job.id)) { clearInterval(cancelWatch); finish({ workerStatus: 'failed', errors: ['cancelled'] }); } }, 500);

    child.on('message', (m) => { clearTimeout(timer); clearInterval(cancelWatch); finish(m.ok ? m.evidence : { workerStatus: 'failed', errors: [m.error] }); });
    child.on('error', (e) => { clearTimeout(timer); clearInterval(cancelWatch); finish({ workerStatus: 'failed', errors: [e.message] }); });
    child.on('exit', () => { clearTimeout(timer); clearInterval(cancelWatch); if (!done) finish({ workerStatus: 'failed', errors: ['worker exited'] }); });

    child.send({
      url: job.normalized,
      allowHosts,
      navTimeoutMs: sandboxConfig.navTimeoutMs,
      maxRedirects: sandboxConfig.maxRedirects,
      maxResponseBytes: sandboxConfig.maxResponseBytes,
      screenshotPath,
      screenshotMaxBytes: sandboxConfig.screenshotMaxBytes,
    });
  });
}

// --- retention cleanup ---
export async function runCleanup() {
  const expired = await store.findExpired();
  for (const j of expired) {
    if (j.screenshotPath) await fs.unlink(j.screenshotPath).catch(() => {});
    await store.markExpired(j.id);
  }
  return expired.length;
}

let cleanupTimer = null;
export function startCleanupLoop() {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => { runCleanup().catch(() => {}); }, sandboxConfig.cleanupIntervalMs);
  cleanupTimer.unref?.();
}

export const _internal = { dynamicPermitted, ARTIFACT_DIR };
