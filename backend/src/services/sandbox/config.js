// Threat Sandbox configuration — all limits are env-driven with safe defaults.
// SECURITY: arbitrary public-URL browsing is DISABLED by default in this preview.
function num(name, def) {
  const v = parseInt(process.env[name], 10);
  return Number.isFinite(v) ? v : def;
}
function bool(name, def) {
  const v = process.env[name];
  if (v === undefined) return def;
  return v === 'true' || v === '1';
}
function list(name) {
  return (process.env[name] || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
}

export const sandboxConfig = {
  // Reduced-isolation notice surfaced in every report.
  isolationMode: process.env.SANDBOX_ISOLATION_MODE || 'development-reduced-isolation',
  analysisVersion: '1.0.0',

  // Dynamic (Playwright) browsing gates.
  allowPublic: bool('SANDBOX_ALLOW_PUBLIC', false),      // browse arbitrary public URLs
  allowTestOrigins: bool('SANDBOX_ALLOW_TEST_ORIGINS', false), // permit fixture origins (tests only)
  allowlistHosts: list('SANDBOX_ALLOWLIST_HOSTS'),       // explicitly permitted public hosts
  testOrigins: list('SANDBOX_TEST_ORIGINS'),             // e.g. http://127.0.0.1:8092

  // Limits.
  concurrency: num('SANDBOX_CONCURRENCY', 1),
  navTimeoutMs: num('SANDBOX_NAV_TIMEOUT_MS', 20000),
  jobTimeoutMs: num('SANDBOX_JOB_TIMEOUT_MS', 45000),
  maxRedirects: num('SANDBOX_MAX_REDIRECTS', 10),
  maxResponseBytes: num('SANDBOX_MAX_RESPONSE_BYTES', 5 * 1024 * 1024),
  maxUrlLength: num('SANDBOX_MAX_URL_LENGTH', 2048),
  screenshotMaxBytes: num('SANDBOX_SCREENSHOT_MAX_BYTES', 3 * 1024 * 1024),

  // Retention / cleanup.
  retentionMinutes: num('SANDBOX_RETENTION_MINUTES', 60),
  cleanupIntervalMs: num('SANDBOX_CLEANUP_INTERVAL_MS', 5 * 60 * 1000),
};
