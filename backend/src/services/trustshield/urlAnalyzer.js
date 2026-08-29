import { BRANDS, SUSPICIOUS_TLDS } from './constants.js';
import { makeSignal, levenshtein, deleet, safeParseUrl } from './utils.js';

const CREDENTIAL_RE = /(login|log-in|signin|sign-in|verify|verification|account|secure|update|confirm|password|credential|auth|webscr|recover|unlock)/i;
const PAYMENT_RE = /(payment|billing|invoice|wallet|bank|transfer|refund|checkout|deposit|kyc)/i;

function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

// Detect brand impersonation / typosquatting on the hostname labels.
function detectBrandImpersonation(hostname) {
  const parts = hostname.split('.');
  const registrable = parts.slice(-2).join('.');
  for (const brand of BRANDS) {
    if (hostname === brand.domain || hostname.endsWith('.' + brand.domain)) return null; // legitimate
  }
  for (const brand of BRANDS) {
    for (const label of parts.slice(0, -1)) { // skip the TLD label
      const norm = deleet(label);
      if (norm === brand.name && registrable !== brand.domain) {
        return brand.name;
      }
      if (brand.name.length >= 5 && Math.abs(norm.length - brand.name.length) <= 1 &&
          levenshtein(norm, brand.name) === 1 && norm !== brand.name) {
        return brand.name;
      }
    }
  }
  return null;
}

// Analyze a single URL string. Returns { signals, parsed, host } — signals is an
// internal list (see utils.makeSignal). Purely offline: no network requests.
export function analyzeUrlString(raw) {
  const url = safeParseUrl(raw);
  if (!url) return { signals: [], parsed: null, host: null, invalid: true };

  const host = url.hostname.toLowerCase();
  const pathQuery = (url.pathname + url.search).toLowerCase();
  const full = url.href;
  const haystack = host + pathQuery;
  const signals = [];

  if (isIpHost(host)) signals.push(makeSignal('IP_HOSTNAME'));
  if (url.protocol !== 'https:') signals.push(makeSignal('NO_HTTPS'));
  if (host.includes('xn--')) signals.push(makeSignal('PUNYCODE_DOMAIN'));
  if (url.username) signals.push(makeSignal('AT_SYMBOL_OBFUSCATION'));

  const pctCount = (full.match(/%[0-9a-f]{2}/gi) || []).length;
  if (pctCount >= 4 || /[^\x00-\x7F]/.test(host)) signals.push(makeSignal('SUSPICIOUS_ENCODING'));

  if (full.length > 75) signals.push(makeSignal('LONG_URL'));
  if (parts_len(host) >= 5) signals.push(makeSignal('EXCESSIVE_SUBDOMAINS'));
  if (CREDENTIAL_RE.test(haystack)) signals.push(makeSignal('CREDENTIAL_KEYWORDS'));
  if (PAYMENT_RE.test(haystack)) signals.push(makeSignal('PAYMENT_KEYWORDS'));

  const tld = host.split('.').pop();
  if (SUSPICIOUS_TLDS.has(tld)) signals.push(makeSignal('SUSPICIOUS_TLD'));

  const brand = detectBrandImpersonation(host);
  if (brand) {
    signals.push(makeSignal('BRAND_IMPERSONATION', {
      description: `The domain "${host}" imitates the well-known brand "${brand}" but is not its official domain, a classic impersonation tactic.`
    }));
  }

  return { signals, parsed: url, host, invalid: false };
}

function parts_len(host) {
  return host.split('.').length;
}
