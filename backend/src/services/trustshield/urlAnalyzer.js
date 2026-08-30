import { BRANDS, SUSPICIOUS_TLDS, TRUSTED_DOMAINS } from './constants.js';
import { makeSignal, levenshtein, deleet, safeParseUrl } from './utils.js';

const CREDENTIAL_RE = /(login|log-in|signin|sign-in|verify|verification|account|secure|update|confirm|password|credential|auth|webscr|recover|unlock)/i;
const PAYMENT_RE = /(payment|billing|invoice|wallet|bank|transfer|refund|checkout|deposit|kyc)/i;

export function isIpHost(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(':');
}

// Numeric feature vector used by the ML service. Kept in sync with ml-service.
export function extractUrlFeatures(url) {
  const host = url.hostname.toLowerCase();
  const hay = (host + url.pathname + url.search).toLowerCase();
  return {
    urlLength: url.href.length,
    hostnameLength: host.length,
    pathLength: url.pathname.length,
    subdomainCount: Math.max(0, host.split('.').length - 2),
    hasIpHost: isIpHost(host) ? 1 : 0,
    hasPunycode: host.includes('xn--') ? 1 : 0,
    hasAtSymbol: url.username ? 1 : 0,
    digitCount: (host.match(/\d/g) || []).length,
    hasHttps: url.protocol === 'https:' ? 1 : 0,
    suspiciousKeyword: (CREDENTIAL_RE.test(hay) || PAYMENT_RE.test(hay)) ? 1 : 0
  };
}

// Detect brand impersonation / typosquatting on the hostname labels.
function detectBrandImpersonation(hostname) {
  const parts = hostname.split('.');
  const registrable = parts.slice(-2).join('.');
  for (const brand of BRANDS) {
    if (hostname === brand.domain || hostname.endsWith('.' + brand.domain)) return null; // legitimate
  }
  const labels = parts.slice(0, -1); // skip the TLD label
  for (const brand of BRANDS) {
    for (const label of labels) {
      // split composite labels (e.g. "amaz0n-account-verify") into words + whole label
      const words = label.split(/[-_]+/).filter(Boolean).concat(label);
      for (const w of words) {
        const norm = deleet(w);
        // exact brand token appearing in a non-official domain
        if (norm === brand.name && registrable !== brand.domain) return brand.name;
        // one-edit typo of the brand (length-bounded to keep false positives low)
        if (brand.name.length >= 5 && Math.abs(norm.length - brand.name.length) <= 1 &&
            levenshtein(norm, brand.name) === 1 && norm !== brand.name) return brand.name;
      }
    }
  }
  return null;
}

// Analyze a single URL string. Returns { signals, parsed, host } — signals is an
// internal list (see utils.makeSignal). Purely offline: no network requests.
// True if the host is (a subdomain of) a well-known trusted domain.
function isTrustedHost(host) {
  for (const d of TRUSTED_DOMAINS) {
    if (host === d || host.endsWith('.' + d)) return true;
  }
  return false;
}

export function analyzeUrlString(raw) {
  const url = safeParseUrl(raw);
  if (!url) return { signals: [], parsed: null, host: null, invalid: true };

  const host = url.hostname.toLowerCase();

  // Trusted domains short-circuit to a clean, safe result (no false positives).
  if (isTrustedHost(host)) return { signals: [], parsed: url, host, invalid: false };

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
