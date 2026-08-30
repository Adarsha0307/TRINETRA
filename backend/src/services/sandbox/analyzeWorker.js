// ---------------------------------------------------------------------------
// Disposable analysis worker — runs in a SEPARATE process (never in the API
// process). Launches a fresh headless browser, collects defensive telemetry
// only, then exits. Receives a job over IPC and returns evidence over IPC.
//
// NOTE (preview): this provides PROCESS separation, which is NOT equivalent to
// container isolation. Production must run this behind the provided Docker/K8s
// hardening (read-only rootfs, dropped caps, no-new-privileges, resource caps).
// ---------------------------------------------------------------------------
import fs from 'fs/promises';
import { assertDestinationAllowed, normalizeHostIp, classifyIp } from './ssrf.js';

function registrableDomain(host) {
  const parts = (host || '').split('.');
  return parts.slice(-2).join('.');
}

async function analyze(job) {
  const allowHosts = new Set(job.allowHosts || []);
  const { chromium } = await import('playwright');
  const evidence = {
    finalUrl: null, finalDomain: null, httpStatus: null, redirectChain: [],
    title: null, tls: null, securityHeaders: null, forms: {}, externalScripts: [],
    obfuscationIndicators: [], downloadAttempts: [], crossDomainRedirect: false,
    screenshotPath: null, workerStatus: 'completed', errors: [],
  };
  const start = Date.now();
  let browser;
  try {
    browser = await chromium.launch({
      headless: true,
      args: ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu',
        '--disable-extensions', '--disable-background-networking', '--disable-sync'],
    });
    const context = await browser.newContext({
      acceptDownloads: false,          // downloads blocked
      serviceWorkers: 'block',
      javaScriptEnabled: true,
      bypassCSP: false,
      permissions: [],                 // deny all permissions
      userAgent: 'ClickShieldSandbox/1.0 (+isolated-analysis)',
    });
    context.setDefaultNavigationTimeout(job.navTimeoutMs);

    // Block non-http(s) and obviously-blocked literal hosts at request time.
    await context.route('**/*', route => {
      try {
        const u = new URL(route.request().url());
        if (u.protocol !== 'http:' && u.protocol !== 'https:') return route.abort();
        if (allowHosts.has(u.hostname.toLowerCase())) return route.continue();
        const lit = normalizeHostIp(u.hostname.toLowerCase());
        if (lit && classifyIp(lit).blocked) return route.abort();
        if (u.hostname === 'localhost' || u.hostname.endsWith('.localhost')) return route.abort();
      } catch { return route.abort(); }
      return route.continue();
    });

    const page = await context.newPage();
    context.on('download', d => { evidence.downloadAttempts.push(String(d.suggestedFilename() || 'download')); d.cancel().catch(() => {}); });

    const seenNav = new Set();
    page.on('response', resp => {
      try {
        const req = resp.request();
        if (req.isNavigationRequest() && req.frame() === page.mainFrame()) {
          const url = resp.url();
          if (!seenNav.has(url)) { seenNav.add(url); evidence.redirectChain.push({ url, status: resp.status() }); }
        }
      } catch { /* ignore */ }
    });

    const response = await page.goto(job.url, { waitUntil: 'domcontentloaded' });
    await page.waitForTimeout(800); // allow late redirects/scripts to settle

    evidence.finalUrl = page.url();
    evidence.finalDomain = registrableDomain(new URL(evidence.finalUrl).hostname);

    // Revalidate the FINAL destination against SSRF rules (defends redirects/rebinding).
    const finalHost = new URL(evidence.finalUrl).hostname.toLowerCase();
    if (!allowHosts.has(finalHost)) {
      try { await assertDestinationAllowed(evidence.finalUrl); }
      catch (e) { evidence.errors.push(`final-url blocked: ${e.message}`); evidence.workerStatus = 'blocked'; }
    }

    if (response) {
      evidence.httpStatus = response.status();
      const headers = response.headers();
      const wanted = ['content-security-policy', 'strict-transport-security', 'x-frame-options', 'x-content-type-options', 'referrer-policy'];
      const missing = wanted.filter(h => !headers[h]);
      evidence.securityHeaders = { present: wanted.filter(h => headers[h]), missingCount: missing.length, missing };
      try {
        const sec = await response.securityDetails();
        if (sec) {
          const validTo = sec.validTo ? sec.validTo * 1000 : null;
          evidence.tls = { issuer: sec.issuer, subject: sec.subjectName, protocol: sec.protocol,
            validFrom: sec.validFrom, validTo: sec.validTo, valid: validTo ? validTo > Date.now() : null };
        } else if (evidence.finalUrl.startsWith('https://')) {
          evidence.tls = { valid: null, note: 'no security details available' };
        }
      } catch { /* http or unavailable */ }
    }

    try { evidence.title = await page.title(); } catch { /* ignore */ }

    // On-page telemetry (defensive only — never executes page code we return).
    try {
      const pageHost = new URL(evidence.finalUrl).hostname;
      const dom = await page.evaluate((host) => {
        const q = (sel) => Array.from(document.querySelectorAll(sel));
        const inputs = q('input');
        const hasPassword = inputs.some(i => i.type === 'password');
        const hasOtp = inputs.some(i => /otp|one[-_]?time|verif|code|token|2fa/i.test((i.name || '') + (i.id || '') + (i.autocomplete || '')));
        const hasPayment = inputs.some(i => /card|cc[-_]?num|cvv|cvc|credit|payment|iban/i.test((i.name || '') + (i.id || '') + (i.autocomplete || '')));
        let crossDomainAction = null;
        for (const f of q('form')) {
          if (f.action) { try { const a = new URL(f.action, location.href); if (a.hostname && a.hostname !== host) { crossDomainAction = a.hostname; break; } } catch { /* */ } }
        }
        const scripts = q('script[src]').map(s => { try { return new URL(s.src, location.href).hostname; } catch { return null; } }).filter(Boolean);
        const externalScripts = [...new Set(scripts.filter(h => h !== host))];
        const inlineText = q('script:not([src])').map(s => s.textContent || '').join('\n').slice(0, 200000);
        const obf = [];
        if (/eval\s*\(/.test(inlineText)) obf.push('eval()');
        if (/atob\s*\(|unescape\s*\(|fromCharCode/.test(inlineText)) obf.push('decode/deobfuscation calls');
        if (/(\\x[0-9a-f]{2}){8,}/i.test(inlineText)) obf.push('long hex-escaped strings');
        if (/document\.write\s*\(/.test(inlineText)) obf.push('document.write()');
        const iframeCount = q('iframe').length;
        return { hasPassword, hasOtp, hasPayment, crossDomainAction, externalScripts, obf, iframeCount, title: document.title };
      }, pageHost);
      evidence.forms = { hasPassword: dom.hasPassword, hasOtp: dom.hasOtp, hasPayment: dom.hasPayment, crossDomainAction: dom.crossDomainAction };
      evidence.externalScripts = dom.externalScripts;
      evidence.obfuscationIndicators = dom.obf;
      evidence.iframeCount = dom.iframeCount;
    } catch (e) { evidence.errors.push(`dom-eval: ${e.message}`); }

    evidence.crossDomainRedirect = evidence.redirectChain.length > 0 &&
      registrableDomain(new URL(job.url).hostname) !== evidence.finalDomain;

    // Screenshot (only if under size cap; artifact is temporary).
    if (job.screenshotPath && evidence.workerStatus === 'completed') {
      try {
        const buf = await page.screenshot({ type: 'jpeg', quality: 60, fullPage: false });
        if (buf.length <= job.screenshotMaxBytes) { await fs.writeFile(job.screenshotPath, buf); evidence.screenshotPath = job.screenshotPath; }
      } catch (e) { evidence.errors.push(`screenshot: ${e.message}`); }
    }
  } catch (e) {
    evidence.workerStatus = 'failed';
    evidence.errors.push(e.message);
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
  evidence.durationMs = Date.now() - start;
  return evidence;
}

process.on('message', async (job) => {
  try {
    const evidence = await analyze(job);
    process.send({ ok: true, evidence });
  } catch (e) {
    process.send({ ok: false, error: e.message });
  } finally {
    setTimeout(() => process.exit(0), 50);
  }
});
