import { sandboxConfig } from './config.js';

// URL normalization + validation for the sandbox. Does NOT resolve DNS
// (see ssrf.js for network validation).
export class UrlValidationError extends Error {
  constructor(message) { super(message); this.name = 'UrlValidationError'; this.status = 400; }
}

// Redact query-parameter values that look like tokens / PII before storing or logging.
const SENSITIVE_PARAM = /(token|auth|key|secret|password|passwd|pwd|otp|session|sid|jwt|access|refresh|email|phone|card|cvv|ssn|account)/i;

export function redactUrl(rawUrl) {
  try {
    const u = new URL(rawUrl);
    for (const k of [...u.searchParams.keys()]) {
      if (SENSITIVE_PARAM.test(k)) u.searchParams.set(k, '[REDACTED]');
    }
    if (u.username || u.password) { u.username = ''; u.password = ''; }
    return u.href;
  } catch { return '[unparseable-url]'; }
}

// A safe, short label for logs — host + path only, no query, no credentials.
export function safeUrlLabel(rawUrl) {
  try { const u = new URL(rawUrl); return `${u.protocol}//${u.host}${u.pathname}`.slice(0, 120); }
  catch { return '[unparseable-url]'; }
}

// Normalize an input URL string. Returns { normalized, original }.
export function normalizeUrl(input) {
  if (typeof input !== 'string' || !input.trim()) throw new UrlValidationError('A URL string is required.');
  let raw = input.trim();
  if (raw.length > sandboxConfig.maxUrlLength) throw new UrlValidationError(`URL exceeds ${sandboxConfig.maxUrlLength} characters.`);
  if (/[\s<>]/.test(raw)) throw new UrlValidationError('URL contains whitespace or angle brackets.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = 'https://' + raw;

  let u;
  try { u = new URL(raw); } catch { throw new UrlValidationError('URL is malformed.'); }

  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new UrlValidationError(`Only http and https URLs are supported (got "${u.protocol}").`);
  }
  if (u.username || u.password) throw new UrlValidationError('URLs with embedded credentials are not allowed.');

  u.hostname = u.hostname.toLowerCase();
  // Strip default ports and fragments (fragments never sent to server).
  if ((u.protocol === 'http:' && u.port === '80') || (u.protocol === 'https:' && u.port === '443')) u.port = '';
  u.hash = '';
  return { normalized: u.href, original: input.trim() };
}
