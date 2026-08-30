import { analyzeUrlString } from '../trustshield/urlAnalyzer.js';
import { checkGoogleSafeBrowsing } from '../urlScanner/threatIntel.js';

// Static (no-browser) URL analysis. Reuses the existing rule engine and the
// existing pluggable Safe Browsing check (key-gated). Always safe to run.
export async function staticAnalyze(normalizedUrl) {
  const { signals, host } = analyzeUrlString(normalizedUrl);
  const urlSignals = new Set();
  let lookalikeBrand = null;
  for (const s of signals) {
    if (s.code === 'IP_HOSTNAME') urlSignals.add('IP_URL');
    else if (s.code === 'PUNYCODE_DOMAIN') urlSignals.add('PUNYCODE_DOMAIN');
    else if (s.code === 'BRAND_IMPERSONATION') { urlSignals.add('LOOKALIKE_DOMAIN'); lookalikeBrand = host; }
    else if (s.code === 'CREDENTIAL_KEYWORDS' || s.code === 'PAYMENT_KEYWORDS') urlSignals.add('SUSPICIOUS_URL_KEYWORDS');
  }

  let safeBrowsing = { checked: false, detected: false, note: 'skipped' };
  try {
    const sb = await checkGoogleSafeBrowsing(normalizedUrl);
    const hasKey = !/no api key/i.test(sb.note || '');
    safeBrowsing = { checked: hasKey, detected: !!sb.detected, note: sb.note, ageMs: 0 };
  } catch (err) {
    safeBrowsing = { checked: false, detected: false, note: `error: ${err.message}` };
  }

  return { hostname: host, urlSignals: [...urlSignals], lookalikeBrand, safeBrowsing };
}
