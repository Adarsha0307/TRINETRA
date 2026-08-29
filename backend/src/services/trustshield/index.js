import { analyzeUrlString, extractUrlFeatures } from './urlAnalyzer.js';
import { analyzeContent } from './contentSignals.js';
import { buildResult } from './riskEngine.js';
import { makeSignal } from './utils.js';
import { predictUrl } from './mlClient.js';

// Build an ML risk signal from a model probability (or null if not risky/unavailable).
async function mlUrlSignal(parsed) {
  if (!parsed) return { signal: null, ml: null };
  const features = extractUrlFeatures(parsed);
  const pred = await predictUrl(features);
  if (!pred) return { signal: null, ml: null };
  const pct = Math.round(pred.probability * 100);
  let signal = null;
  const description = `A machine-learning model (${pred.modelVersion}) estimated a ${pct}% phishing likelihood from this URL's structural features.`;
  if (pred.probability >= 0.85) signal = makeSignal('ML_MODEL_RISK', { scoreContribution: 15, severity: 'HIGH', description });
  else if (pred.probability >= 0.6) signal = makeSignal('ML_MODEL_RISK', { scoreContribution: 10, severity: 'MEDIUM', description });
  return { signal, ml: { ...pred, features } };
}

// --- URL (rule-based only; used by tests and embedded-URL analysis) ---
export function scanUrl(rawUrl) {
  const { signals, host, invalid } = analyzeUrlString(rawUrl);
  if (invalid) { const e = new Error('Invalid URL format.'); e.status = 400; throw e; }
  return { result: buildResult('url', signals), preview: host };
}

// --- URL (rule engine + ML) ---
export async function scanUrlAsync(rawUrl) {
  const { signals, host, parsed, invalid } = analyzeUrlString(rawUrl);
  if (invalid) { const e = new Error('Invalid URL format.'); e.status = 400; throw e; }
  const { signal, ml } = await mlUrlSignal(parsed);
  const all = signal ? [...signals, signal] : signals;
  const result = buildResult('url', all);
  result.ml = ml;
  return { result, preview: host };
}

// --- Email --- (rule-based; extracts & analyzes embedded URLs)
export function scanEmail({ sender = '', subject = '', content = '' }) {
  const combined = [subject, content].filter(Boolean).join('\n');
  const signals = analyzeContent(combined + '\n' + (sender || ''));
  if (sender && /@(gmail|yahoo|outlook|hotmail|proton|aol|mail)\./i.test(sender) &&
      signals.some(s => s.code === 'BRAND_IMPERSONATION_CONTENT')) {
    signals.push(makeSignal('BRAND_IMPERSONATION_CONTENT', {
      description: `The sender uses a free/public mailbox (${sender}) while impersonating a brand — a strong phishing indicator.`
    }));
  }
  const preview = sender ? String(sender).split('@').pop()?.slice(0, 60) || null : null;
  return { result: buildResult('email', signals), preview };
}

// --- Message / SMS ---
export function scanMessage({ content = '', sender = '' }) {
  const signals = analyzeContent(content + '\n' + sender);
  return { result: buildResult('message', signals), preview: null };
}

// --- QR (destination already decoded) ---
export async function scanQrContentAsync(content) {
  const text = (content || '').trim();
  const isUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) || /^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(text);
  if (isUrl) {
    const { signals, host, parsed } = analyzeUrlString(text);
    const { signal, ml } = await mlUrlSignal(parsed);
    const all = signal ? [...signals, signal] : signals;
    const result = buildResult('qr', all);
    result.ml = ml;
    return { result, preview: host, decoded: text };
  }
  return { result: buildResult('qr', []), preview: null, decoded: text };
}
