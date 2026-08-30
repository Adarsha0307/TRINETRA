import { sanitizeText, sanitizeUrlString, sanitizeStringArray } from './sanitize.js';

// Neutralize every target-supplied string in a report before it is stored or
// returned. Defense-in-depth (the frontend also renders everything escaped).
export function sanitizeReport(report) {
  const o = report.observed || {};
  return {
    ...report,
    observed: {
      ...o,
      finalUrl: sanitizeUrlString(o.finalUrl),
      finalDomain: sanitizeText(o.finalDomain, 253),
      title: sanitizeText(o.title, 300),
      redirectChain: (o.redirectChain || []).slice(0, 20).map(r => ({
        url: sanitizeUrlString(r.url), status: Number.isFinite(r.status) ? r.status : null,
      })),
      tls: o.tls ? {
        issuer: sanitizeText(o.tls.issuer, 200), subject: sanitizeText(o.tls.subject, 200),
        protocol: sanitizeText(o.tls.protocol, 40), validFrom: o.tls.validFrom ?? null,
        validTo: o.tls.validTo ?? null, valid: o.tls.valid ?? null, note: sanitizeText(o.tls.note, 120),
      } : null,
      securityHeaders: o.securityHeaders ? {
        present: sanitizeStringArray(o.securityHeaders.present, 20, 60),
        missing: sanitizeStringArray(o.securityHeaders.missing, 20, 60),
        missingCount: Number(o.securityHeaders.missingCount) || 0,
      } : null,
    },
    findings: (report.findings || []).map(f => ({
      ...f,
      evidence: sanitizeText(f.evidence, 400),
      title: sanitizeText(f.title, 160),
      whyItMatters: sanitizeText(f.whyItMatters, 400),
      consequence: sanitizeText(f.consequence, 400),
      recommendation: sanitizeText(f.recommendation, 400),
    })),
  };
}
