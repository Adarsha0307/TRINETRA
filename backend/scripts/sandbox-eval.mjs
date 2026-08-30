// Honest evaluation of the DETERMINISTIC RISK-ENGINE SCORING over a labeled set
// of synthetic evidence bundles (NOT a measure of live real-world detection
// accuracy — no live sites are used). Reproducible: node scripts/sandbox-eval.mjs
import { buildReport } from '../src/services/sandbox/riskEngine.js';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const base = { analysisVersion: '1.0.0', isolationMode: 'evaluation', normalizedUrl: 'https://x', hostname: 'x' };
const noSB = { checked: false };

// label: 'malicious' (should be flagged) | 'benign' (should not be flagged)
const CASES = [
  { name: 'clean-benign', label: 'benign', ev: { ...base, urlSignals: [], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: noSB, forms: {}, finalUrl: 'https://a.com', redirectChain: [], securityHeaders: { missingCount: 0, missing: [] } } },
  { name: 'benign-http-only', label: 'benign', ev: { ...base, urlSignals: [], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: noSB, forms: {}, finalUrl: 'http://a.com', redirectChain: [], securityHeaders: { missingCount: 1, missing: ['csp'] } } },
  { name: 'benign-login-legit', label: 'benign', ev: { ...base, urlSignals: [], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: noSB, forms: { hasPassword: true, crossDomainAction: null }, finalUrl: 'https://a.com', redirectChain: [] } },
  { name: 'lookalike-only', label: 'malicious', ev: { ...base, urlSignals: ['LOOKALIKE_DOMAIN'], lookalikeBrand: 'paypal', dynamicPerformed: false, safeBrowsing: noSB } },
  { name: 'phish-credform-crossdomain', label: 'malicious', ev: { ...base, urlSignals: ['LOOKALIKE_DOMAIN'], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: noSB, forms: { hasPassword: true, hasOtp: true, crossDomainAction: 'evil.com' }, finalUrl: 'https://a.com', redirectChain: [] } },
  { name: 'auto-download', label: 'malicious', ev: { ...base, urlSignals: [], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: noSB, forms: {}, downloadAttempts: ['x.exe'], finalUrl: 'https://a.com', redirectChain: [] } },
  { name: 'known-malicious-reputation', label: 'malicious', ev: { ...base, urlSignals: [], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: { checked: true, detected: true, note: 'MALWARE', ageMs: 0 }, forms: {}, finalUrl: 'https://a.com', redirectChain: [] } },
  { name: 'punycode+keywords', label: 'malicious', ev: { ...base, urlSignals: ['PUNYCODE_DOMAIN', 'SUSPICIOUS_URL_KEYWORDS'], dynamicPerformed: false, safeBrowsing: noSB } },
  { name: 'ip-url', label: 'malicious', ev: { ...base, urlSignals: ['IP_URL', 'SUSPICIOUS_URL_KEYWORDS'], dynamicPerformed: false, safeBrowsing: noSB } },
  { name: 'excessive-redirects', label: 'malicious', ev: { ...base, urlSignals: ['LOOKALIKE_DOMAIN'], dynamicPerformed: true, workerStatus: 'completed', safeBrowsing: noSB, forms: {}, redirectChain: [1, 2, 3, 4, 5, 6].map(i => ({ url: 'https://r' + i })), crossDomainRedirect: true, finalDomain: 'z.com', finalUrl: 'https://z.com' } },
];

let tp = 0, tn = 0, fp = 0, fn = 0, inconclusive = 0;
const rows = [];
for (const c of CASES) {
  const r = buildReport(c.ev);
  const predictedMalicious = ['Suspicious', 'High risk', 'Known malicious'].includes(r.riskLevel);
  if (r.riskLevel === 'Inconclusive') inconclusive++;
  const actualMalicious = c.label === 'malicious';
  if (predictedMalicious && actualMalicious) tp++;
  else if (!predictedMalicious && !actualMalicious) tn++;
  else if (predictedMalicious && !actualMalicious) fp++;
  else fn++;
  rows.push({ name: c.name, label: c.label, level: r.riskLevel, score: r.riskScore, predictedMalicious });
}

const precision = tp + fp ? tp / (tp + fp) : 0;
const recall = tp + fn ? tp / (tp + fn) : 0;
const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
const accuracy = (tp + tn) / CASES.length;

const results = {
  disclaimer: 'This evaluates the DETERMINISTIC RISK-ENGINE SCORING on synthetic labeled evidence bundles. It is NOT a measure of live, real-world phishing/malware detection accuracy. No live websites were used.',
  generatedAt: new Date().toISOString(),
  cases: CASES.length,
  confusionMatrix: { tp, tn, fp, fn },
  precision: +precision.toFixed(4), recall: +recall.toFixed(4), f1: +f1.toFixed(4), accuracy: +accuracy.toFixed(4),
  inconclusiveRate: +(inconclusive / CASES.length).toFixed(4),
  rows,
};

const outDir = path.join(path.dirname(fileURLToPath(import.meta.url)), '../../test_reports');
fs.mkdirSync(outDir, { recursive: true });
fs.writeFileSync(path.join(outDir, 'sandbox-eval-results.json'), JSON.stringify(results, null, 2));
console.log(JSON.stringify(results, null, 2));
