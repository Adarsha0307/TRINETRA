import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import http from 'http';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FIXTURES = path.join(__dirname, 'fixtures');

let server, port, jm, store, db;
const createdIds = [];

// Detect Playwright availability so the dynamic test can be skipped cleanly.
let hasPw = true;
try { await import('playwright'); } catch { hasPw = false; }

beforeAll(async () => {
  server = http.createServer(async (req, res) => {
    const file = req.url.includes('phish') ? 'phish-login.html' : 'benign.html';
    try {
      const html = await fs.readFile(path.join(FIXTURES, file), 'utf-8');
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(html);
    } catch { res.writeHead(404); res.end('nf'); }
  });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  port = server.address().port;

  // Configure BEFORE importing the manager (config reads env at import time).
  process.env.SANDBOX_ALLOW_TEST_ORIGINS = 'true';
  process.env.SANDBOX_TEST_ORIGINS = `http://127.0.0.1:${port}`;
  process.env.SANDBOX_CONCURRENCY = '1';
  process.env.SANDBOX_JOB_TIMEOUT_MS = '40000';
  process.env.PLAYWRIGHT_BROWSERS_PATH = process.env.PLAYWRIGHT_BROWSERS_PATH || '/pw-browsers';

  jm = await import('../src/services/sandbox/jobManager.js');
  store = await import('../src/services/sandbox/jobStore.js');
  db = await import('../src/utils/db.js');
});

afterAll(async () => {
  for (const id of createdIds) await store.deleteJob(id).catch(() => {});
  if (server) await new Promise(r => server.close(r));
});

async function waitFor(id, ms = 45000) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    const j = await store.getJob(id);
    if (j && (j.status === 'completed' || j.status === 'failed' || j.status === 'expired')) return j;
    await new Promise(r => setTimeout(r, 500));
  }
  return store.getJob(id);
}

describe.skipIf(!hasPw)('Sandbox worker + lifecycle (real Playwright, local fixtures)', () => {
  it('runs dynamic analysis on a credential-phishing fixture and collects real evidence', async () => {
    const { id } = await jm.enqueueJob(`http://127.0.0.1:${port}/phish-login.html`);
    createdIds.push(id);
    const job = await waitFor(id);
    expect(job.status).toBe('completed');
    expect(job.report.observed.dynamicPerformed).toBe(true);
    const codes = job.report.findings.map(f => f.code);
    expect(codes).toContain('CREDENTIAL_FORM');
    expect(codes).toContain('SUSPICIOUS_FORM_ACTION');
    expect(job.report.observed.title).toBeTruthy();
    // screenshot artifact should exist
    expect(job.screenshotPath).toBeTruthy();
    await expect(fs.access(job.screenshotPath)).resolves.toBeUndefined();
  }, 60000);

  it('completes a benign fixture without high-risk findings', async () => {
    const { id } = await jm.enqueueJob(`http://127.0.0.1:${port}/benign.html`);
    createdIds.push(id);
    const job = await waitFor(id);
    expect(job.status).toBe('completed');
    expect(job.report.observed.dynamicPerformed).toBe(true);
    expect(['Low observed risk', 'Inconclusive', 'Suspicious']).toContain(job.report.riskLevel);
  }, 60000);

  it('cleans up expired artifacts and purges the report', async () => {
    const { id } = await jm.enqueueJob(`http://127.0.0.1:${port}/phish-login.html`);
    createdIds.push(id);
    const job = await waitFor(id);
    const shot = job.screenshotPath;
    // force-expire and run cleanup
    await db.query('UPDATE sandbox_jobs SET expires_at = NOW() - INTERVAL \'1 minute\' WHERE id=$1', [id]);
    const purged = await jm.runCleanup();
    expect(purged).toBeGreaterThanOrEqual(1);
    const after = await store.getJob(id);
    expect(after.status).toBe('expired');
    expect(after.report).toBeNull();
    if (shot) await expect(fs.access(shot)).rejects.toBeTruthy();
  }, 60000);
});

describe('Sandbox lifecycle: SSRF-blocked job fails (no worker)', () => {
  it('fails a metadata URL during validation', async () => {
    const jmL = jm || await import('../src/services/sandbox/jobManager.js');
    const storeL = store || await import('../src/services/sandbox/jobStore.js');
    const { id } = await jmL.enqueueJob('http://169.254.169.254/latest/meta-data/');
    createdIds.push(id);
    const job = await waitFor(id, 10000);
    expect(job.status).toBe('failed');
    expect(job.error).toMatch(/blocked/i);
  }, 15000);
});
