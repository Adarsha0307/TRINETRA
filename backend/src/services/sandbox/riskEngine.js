// ---------------------------------------------------------------------------
// Deterministic, evidence-based risk engine for the Threat Sandbox.
// Each signal has a documented weight, a source category, and requires real
// evidence. Confidence reflects EVIDENCE COMPLETENESS, not the risk score.
// No hard-coded verdicts: every field is derived from the `evidence` argument.
// ---------------------------------------------------------------------------

// source ∈ observed | reputation | rule | heuristic
const SIGNALS = {
  SAFE_BROWSING_MALICIOUS: { title: 'Flagged by Google Safe Browsing', weight: 60, source: 'reputation', why: 'A trusted reputation provider lists this URL as malicious.', consequence: 'Visiting may install malware or steal credentials.', action: 'Do not visit. Treat as confirmed malicious.' },
  LOOKALIKE_DOMAIN: { title: 'Look-alike / typosquatted brand domain', weight: 20, source: 'heuristic', why: 'The domain imitates a well-known brand but is not its official domain.', consequence: 'Users may be tricked into trusting a fake site.', action: 'Verify the official domain independently before trusting.' },
  PUNYCODE_DOMAIN: { title: 'Punycode / internationalized domain', weight: 15, source: 'rule', why: 'IDN/punycode can disguise look-alike characters to imitate a brand.', consequence: 'The displayed domain may differ from the real one.', action: 'Inspect the decoded domain carefully.' },
  IP_URL: { title: 'Direct IP-address URL', weight: 15, source: 'rule', why: 'Links to a raw IP instead of a domain are commonly used to hide destinations.', consequence: 'Obscures the true owner of the destination.', action: 'Be cautious; legitimate services rarely use raw IPs.' },
  CREDENTIAL_FORM: { title: 'Credential (password) form present', weight: 18, source: 'observed', why: 'The page collects a password.', consequence: 'Credentials entered could be harvested.', action: 'Never enter credentials unless the site is verified.' },
  OTP_FORM: { title: 'OTP / verification-code field present', weight: 15, source: 'observed', why: 'The page requests a one-time code.', consequence: 'OTP theft can bypass two-factor authentication.', action: 'Never share OTPs with a site you did not initiate.' },
  PAYMENT_FORM: { title: 'Payment / card field present', weight: 15, source: 'observed', why: 'The page collects payment details.', consequence: 'Card details could be stolen.', action: 'Only enter payment details on verified merchants.' },
  SUSPICIOUS_FORM_ACTION: { title: 'Form submits to a different domain', weight: 20, source: 'observed', why: 'A form posts data to a domain different from the page it appears on.', consequence: 'Entered data may be exfiltrated to a third party.', action: 'Do not submit; the destination is not what it appears.' },
  AUTO_DOWNLOAD: { title: 'Automatic download attempt', weight: 30, source: 'observed', why: 'The page tried to download a file automatically.', consequence: 'Drive-by downloads can deliver malware.', action: 'Do not open any downloaded file.' },
  OBFUSCATED_SCRIPT: { title: 'Obfuscated script indicators', weight: 10, source: 'heuristic', why: 'Scripts show patterns often used to hide malicious behavior.', consequence: 'May conceal exploit or redirect logic.', action: 'Treat interactive elements with suspicion.' },
  EXCESSIVE_REDIRECTS: { title: 'Excessive redirects', weight: 10, source: 'observed', why: 'The URL bounced through many redirects.', consequence: 'Redirect chains are used to evade detection.', action: 'Distrust the final destination.' },
  CROSS_DOMAIN_REDIRECT: { title: 'Cross-domain redirect', weight: 8, source: 'observed', why: 'The URL redirected to a different registrable domain.', consequence: 'You may end up somewhere other than expected.', action: 'Confirm the final domain is trustworthy.' },
  NO_TLS_FINAL: { title: 'Final page not served over HTTPS', weight: 8, source: 'observed', why: 'The final page used an unencrypted connection.', consequence: 'Traffic can be intercepted or altered.', action: 'Avoid entering any data.' },
  TLS_INVALID: { title: 'Invalid / untrusted TLS certificate', weight: 15, source: 'observed', why: 'The certificate is expired, self-signed, or mismatched.', consequence: 'The connection cannot be trusted.', action: 'Do not proceed.' },
  MISSING_SECURITY_HEADERS: { title: 'Missing key security headers', weight: 3, source: 'heuristic', why: 'Common protective headers are absent.', consequence: 'Weak signal; well-run sites usually set these.', action: 'Consider as minor supporting evidence only.' },
  MANY_EXTERNAL_SCRIPTS: { title: 'Many external scripts', weight: 5, source: 'heuristic', why: 'The page loads many third-party scripts.', consequence: 'Increases attack surface; weak signal alone.', action: 'Supporting evidence only.' },
  SUSPICIOUS_URL_KEYWORDS: { title: 'Credential/payment keywords in URL', weight: 10, source: 'heuristic', why: 'The URL path contains login/verify/payment keywords common in phishing.', consequence: 'Often used to impersonate account pages.', action: 'Supporting evidence only.' },
};

const now = () => new Date().toISOString();

function mk(code, evidenceText, confidence = 0.7) {
  const s = SIGNALS[code];
  return {
    code, title: s.title, source: s.source, weight: s.weight,
    evidence: evidenceText, whyItMatters: s.why, consequence: s.consequence,
    recommendation: s.action, confidence, timestamp: now(),
  };
}

// Map completeness ratio -> confidence label.
function confidenceLabel(ratio) {
  if (ratio >= 0.75) return 'high';
  if (ratio >= 0.45) return 'medium';
  return 'low';
}

// Build the full explainable report from collected evidence.
export function buildReport(evidence) {
  const findings = [];
  const notCollected = [];
  const sources = [{ name: 'ClickShield deterministic rules', type: 'rule' }];

  // --- reputation (Safe Browsing, optional/pluggable) ---
  const sb = evidence.safeBrowsing;
  if (sb && sb.checked) {
    sources.push({ name: 'Google Safe Browsing', type: 'reputation', freshnessMs: sb.ageMs ?? 0, note: sb.note });
    if (sb.detected) findings.push(mk('SAFE_BROWSING_MALICIOUS', `Safe Browsing: ${sb.note || 'listed'}`, 0.9));
  } else {
    notCollected.push('Google Safe Browsing verdict (no API key configured or check skipped)');
  }

  // --- static URL signals (always available) ---
  for (const s of evidence.urlSignals || []) {
    if (s === 'PUNYCODE_DOMAIN') findings.push(mk('PUNYCODE_DOMAIN', `Hostname contains punycode: ${evidence.hostname}`, 0.9));
    else if (s === 'IP_URL') findings.push(mk('IP_URL', `Host is a raw IP: ${evidence.hostname}`, 0.95));
    else if (s === 'LOOKALIKE_DOMAIN') findings.push(mk('LOOKALIKE_DOMAIN', `Domain resembles brand "${evidence.lookalikeBrand}"`, 0.8));
    else if (s === 'SUSPICIOUS_URL_KEYWORDS') findings.push(mk('SUSPICIOUS_URL_KEYWORDS', 'Credential/payment keyword found in URL', 0.6));
  }

  // --- dynamic (browser) evidence ---
  if (evidence.dynamicPerformed) {
    sources.push({ name: 'Isolated browser worker (Playwright)', type: 'observed', freshnessMs: 0 });
    const f = evidence.forms || {};
    if (f.hasPassword) findings.push(mk('CREDENTIAL_FORM', 'A password input was detected on the page.', 0.9));
    if (f.hasOtp) findings.push(mk('OTP_FORM', 'An OTP/verification-code input was detected.', 0.85));
    if (f.hasPayment) findings.push(mk('PAYMENT_FORM', 'A payment/card input was detected.', 0.85));
    if (f.crossDomainAction) findings.push(mk('SUSPICIOUS_FORM_ACTION', `A form submits to ${f.crossDomainAction}`, 0.9));
    if ((evidence.downloadAttempts || []).length) findings.push(mk('AUTO_DOWNLOAD', `${evidence.downloadAttempts.length} download attempt(s) blocked.`, 0.95));
    if ((evidence.obfuscationIndicators || []).length) findings.push(mk('OBFUSCATED_SCRIPT', `${evidence.obfuscationIndicators.length} obfuscation indicator(s).`, 0.6));
    if ((evidence.redirectChain || []).length > 4) findings.push(mk('EXCESSIVE_REDIRECTS', `${evidence.redirectChain.length} redirects observed.`, 0.85));
    if (evidence.crossDomainRedirect) findings.push(mk('CROSS_DOMAIN_REDIRECT', `Redirected to ${evidence.finalDomain}`, 0.85));
    if (evidence.finalUrl && evidence.finalUrl.startsWith('http://')) findings.push(mk('NO_TLS_FINAL', 'Final URL is served over HTTP.', 0.9));
    if (evidence.tls && evidence.tls.valid === false) findings.push(mk('TLS_INVALID', evidence.tls.error || 'Certificate not valid.', 0.85));
    if ((evidence.externalScripts || []).length > 15) findings.push(mk('MANY_EXTERNAL_SCRIPTS', `${evidence.externalScripts.length} external scripts.`, 0.5));
    if (evidence.securityHeaders && evidence.securityHeaders.missingCount >= 3) findings.push(mk('MISSING_SECURITY_HEADERS', `${evidence.securityHeaders.missingCount} key headers missing.`, 0.5));
  } else {
    notCollected.push('Dynamic browser analysis (disabled in preview or target not permitted)');
    notCollected.push('TLS certificate inspection', 'Redirect chain', 'On-page form/script telemetry', 'Screenshot');
  }

  // --- dedupe by code (keep first / highest weight) ---
  const seen = new Map();
  for (const f of findings) if (!seen.has(f.code)) seen.set(f.code, f);
  const finalFindings = [...seen.values()];

  const riskScore = Math.max(0, Math.min(100, finalFindings.reduce((sum, f) => sum + f.weight, 0)));

  // --- verdict / risk level ---
  let riskLevel;
  if (evidence.workerStatus === 'failed') riskLevel = 'Analysis failed';
  else if (sb && sb.detected) riskLevel = 'Known malicious';
  else {
    const dynamicOk = evidence.dynamicPerformed || (evidence.urlSignals || []).length > 0;
    if (!dynamicOk && riskScore === 0) riskLevel = 'Inconclusive';
    else if (riskScore >= 70) riskLevel = 'High risk';
    else if (riskScore >= 30) riskLevel = 'Suspicious';
    else riskLevel = 'Low observed risk';
  }

  // --- confidence = evidence completeness (independent of score) ---
  const planned = ['url', 'reputation', 'dynamic'];
  let have = 1; // url signals always attempted
  if (sb && sb.checked) have += 1;
  if (evidence.dynamicPerformed) have += 1;
  const completeness = have / planned.length;
  const confidence = confidenceLabel(completeness);

  const limitations = [
    `Isolation mode: ${evidence.isolationMode}. Process separation is NOT equivalent to container isolation.`,
    'Low observed risk is not proof of safety; absence of evidence is not evidence of absence.',
  ];
  if (!evidence.dynamicPerformed) limitations.push('No live page was rendered; verdict is based on URL/static + reputation signals only.');
  if (!(sb && sb.checked)) limitations.push('No external reputation source was consulted.');

  return {
    schemaVersion: 1,
    analysisVersion: evidence.analysisVersion,
    isolationMode: evidence.isolationMode,
    generatedAt: now(),
    riskScore,
    riskLevel,
    confidence,
    confidenceBasis: `Evidence completeness ${have}/${planned.length} planned sources.`,
    findings: finalFindings,
    evidenceNotCollected: notCollected,
    dataSources: sources,
    limitations,
    observed: {
      normalizedUrl: evidence.normalizedUrl,
      finalUrl: evidence.finalUrl || null,
      finalDomain: evidence.finalDomain || null,
      httpStatus: evidence.httpStatus ?? null,
      redirectChain: evidence.redirectChain || [],
      title: evidence.title || null,
      tls: evidence.tls || null,
      securityHeaders: evidence.securityHeaders || null,
      screenshotAvailable: !!evidence.screenshotPath,
      durationMs: evidence.durationMs ?? null,
      workerStatus: evidence.workerStatus || 'n/a',
      dynamicPerformed: !!evidence.dynamicPerformed,
    },
  };
}
