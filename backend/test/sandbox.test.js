import { describe, it, expect } from 'vitest';
import { classifyIp, normalizeHostIp, assertDestinationAllowed, SsrfError } from '../src/services/sandbox/ssrf.js';
import { normalizeUrl, redactUrl, safeUrlLabel, UrlValidationError } from '../src/services/sandbox/urlNormalize.js';
import { sanitizeText, sanitizeUrlString } from '../src/services/sandbox/sanitize.js';
import { buildReport } from '../src/services/sandbox/riskEngine.js';
import { sanitizeReport } from '../src/services/sandbox/reportSanitizer.js';

const resolver = (addrs) => async () => addrs.map(a => ({ address: a }));

describe('SSRF: IP classification', () => {
  it('blocks loopback / private / link-local / metadata / reserved', () => {
    for (const ip of ['127.0.0.1', '10.1.2.3', '192.168.0.1', '172.16.5.5', '169.254.169.254', '169.254.1.1', '100.64.0.1', '0.0.0.0', '224.0.0.1', '240.0.0.1'])
      expect(classifyIp(ip).blocked, ip).toBe(true);
  });
  it('blocks IPv6 loopback / link-local / ULA / multicast', () => {
    for (const ip of ['::1', 'fe80::1', 'fc00::1', 'fd12::1', 'ff02::1'])
      expect(classifyIp(ip).blocked, ip).toBe(true);
  });
  it('allows normal public IPs', () => {
    for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34'])
      expect(classifyIp(ip).blocked, ip).toBe(false);
  });
});

describe('SSRF: alternate IP encodings', () => {
  it('decodes decimal / hex / octal to detect loopback', () => {
    expect(normalizeHostIp('2130706433')).toBe('127.0.0.1');
    expect(normalizeHostIp('0x7f.0.0.1')).toBe('127.0.0.1');
    expect(classifyIp(normalizeHostIp('2130706433')).blocked).toBe(true);
  });
});

describe('SSRF: assertDestinationAllowed', () => {
  it('rejects unsupported protocols', async () => {
    await expect(assertDestinationAllowed('ftp://example.com')).rejects.toBeInstanceOf(SsrfError);
    await expect(assertDestinationAllowed('file:///etc/passwd')).rejects.toBeInstanceOf(SsrfError);
  });
  it('rejects embedded credentials', async () => {
    await expect(assertDestinationAllowed('http://user:pass@example.com')).rejects.toBeInstanceOf(SsrfError);
  });
  it('rejects internal hostnames and IP literals in blocked ranges', async () => {
    await expect(assertDestinationAllowed('http://localhost/')).rejects.toBeInstanceOf(SsrfError);
    await expect(assertDestinationAllowed('http://169.254.169.254/')).rejects.toBeInstanceOf(SsrfError);
    await expect(assertDestinationAllowed('http://2130706433/')).rejects.toBeInstanceOf(SsrfError);
  });
  it('blocks when DNS resolves to a private address (rebinding defense)', async () => {
    await expect(assertDestinationAllowed('http://rebind.example/', { resolver: resolver(['1.2.3.4', '127.0.0.1']) }))
      .rejects.toBeInstanceOf(SsrfError);
  });
  it('allows a name that resolves only to public addresses', async () => {
    const r = await assertDestinationAllowed('https://good.example/', { resolver: resolver(['93.184.216.34']) });
    expect(r.addresses).toContain('93.184.216.34');
  });
});

describe('URL normalization', () => {
  it('adds https, strips default port, blocks creds and non-http', () => {
    expect(normalizeUrl('example.com').normalized).toBe('https://example.com/');
    expect(normalizeUrl('https://example.com:443/a').normalized).toBe('https://example.com/a');
    expect(() => normalizeUrl('http://u:p@example.com')).toThrow(UrlValidationError);
    expect(() => normalizeUrl('javascript:alert(1)')).toThrow(UrlValidationError);
  });
  it('redacts sensitive query params and never logs full URLs', () => {
    const red = redactUrl('https://x.com/a?token=abc123&q=hi&password=secret');
    expect(red).toContain('token=%5BREDACTED%5D');
    expect(red).toContain('password=%5BREDACTED%5D');
    expect(red).toContain('q=hi');
    expect(safeUrlLabel('https://x.com/p?token=abc')).toBe('https://x.com/p');
  });
});

describe('Output sanitization', () => {
  it('strips control chars and truncates; never returns raw HTML as markup', () => {
    expect(sanitizeText('a\u0000b\u0007c')).toBe('abc');
    expect(sanitizeUrlString('javascript:alert(1)')).not.toMatch(/^javascript:/);
    const rpt = sanitizeReport({ observed: { title: 'x\u0000y', redirectChain: [] }, findings: [{ code: 'C', evidence: 'e\u0007e' }] });
    expect(rpt.observed.title).toBe('xy');
    expect(rpt.findings[0].evidence).toBe('ee');
  });
});

describe('Risk engine (deterministic, evidence-based)', () => {
  const base = { analysisVersion: '1.0.0', isolationMode: 'test', normalizedUrl: 'https://x', hostname: 'x' };

  it('returns Inconclusive with no evidence — never claims safe', () => {
    const r = buildReport({ ...base, urlSignals: [], dynamicPerformed: false, safeBrowsing: { checked: false } });
    expect(r.riskLevel).toBe('Inconclusive');
    expect(r.riskScore).toBe(0);
    expect(r.evidenceNotCollected.length).toBeGreaterThan(0);
  });

  it('marks Known malicious when reputation flags it', () => {
    const r = buildReport({ ...base, urlSignals: [], dynamicPerformed: false, safeBrowsing: { checked: true, detected: true, note: 'MALWARE', ageMs: 0 } });
    expect(r.riskLevel).toBe('Known malicious');
    expect(r.findings.some(f => f.code === 'SAFE_BROWSING_MALICIOUS')).toBe(true);
  });

  it('scores dynamic credential-phishing evidence and dedupes', () => {
    const r = buildReport({ ...base, urlSignals: ['LOOKALIKE_DOMAIN'], lookalikeBrand: 'paypal', dynamicPerformed: true,
      workerStatus: 'completed', safeBrowsing: { checked: false },
      forms: { hasPassword: true, hasOtp: true, crossDomainAction: 'evil.example' },
      redirectChain: [{ url: 'https://x' }], downloadAttempts: [], obfuscationIndicators: ['eval()'], finalUrl: 'https://x' });
    expect(r.riskScore).toBeGreaterThanOrEqual(30);
    expect(['Suspicious', 'High risk']).toContain(r.riskLevel);
    expect(r.findings.some(f => f.code === 'SUSPICIOUS_FORM_ACTION')).toBe(true);
    // confidence reflects completeness, not score
    expect(['low', 'medium', 'high']).toContain(r.confidence);
  });

  it('reports Analysis failed when the worker fails', () => {
    const r = buildReport({ ...base, urlSignals: [], dynamicPerformed: false, workerStatus: 'failed', safeBrowsing: { checked: false } });
    expect(r.riskLevel).toBe('Analysis failed');
  });
});
