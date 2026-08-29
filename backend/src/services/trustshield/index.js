import { analyzeUrlString } from './urlAnalyzer.js';
import { analyzeContent } from './contentSignals.js';
import { buildResult } from './riskEngine.js';
import { makeSignal } from './utils.js';

// --- URL ---
export function scanUrl(rawUrl) {
  const { signals, host, invalid } = analyzeUrlString(rawUrl);
  if (invalid) {
    const e = new Error('Invalid URL format.');
    e.status = 400;
    throw e;
  }
  return { result: buildResult('url', signals), preview: host };
}

// --- Email ---
// Accepts { sender, subject, content }. Combines all provided fields for analysis.
export function scanEmail({ sender = '', subject = '', content = '' }) {
  const combined = [subject, content].filter(Boolean).join('\n');
  const signals = analyzeContent(combined + '\n' + (sender || ''));

  // Sender/brand mismatch: content impersonates a brand but sender is a free mailbox.
  if (sender && /@(gmail|yahoo|outlook|hotmail|proton|aol|mail)\./i.test(sender) &&
      signals.some(s => s.code === 'BRAND_IMPERSONATION_CONTENT')) {
    signals.push(makeSignal('BRAND_IMPERSONATION_CONTENT', {
      description: `The sender uses a free/public mailbox (${sender}) while impersonating a brand — a strong phishing indicator.`
    }));
  }
  // preview: never store raw email content; a coarse sender domain only.
  const preview = sender ? String(sender).split('@').pop()?.slice(0, 60) || null : null;
  return { result: buildResult('email', signals), preview };
}

// --- Message / SMS ---
export function scanMessage({ content = '', sender = '' }) {
  const signals = analyzeContent(content + '\n' + sender);
  return { result: buildResult('message', signals), preview: null };
}

// --- QR (destination already decoded) ---
// content is the decoded text of the QR code.
export function scanQrContent(content) {
  const text = (content || '').trim();
  const isUrl = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) || /^[a-z0-9-]+(\.[a-z0-9-]+)+/i.test(text);
  if (isUrl) {
    const { signals, host } = analyzeUrlString(text);
    return { result: buildResult('qr', signals), preview: host, decoded: text };
  }
  // Non-URL QR payload: no navigable destination, minimal risk.
  return { result: buildResult('qr', []), preview: null, decoded: text };
}
