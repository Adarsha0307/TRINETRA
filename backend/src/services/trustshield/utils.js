import { SIGNAL_DEFS } from './constants.js';

// Build a signal object from the central catalog. Optional overrides let an
// analyzer add context (e.g. the specific brand) to the description.
export function makeSignal(code, overrides = {}) {
  const def = SIGNAL_DEFS[code];
  if (!def) throw new Error(`Unknown signal code: ${code}`);
  return {
    code,
    name: def.name,
    description: overrides.description || def.description,
    scoreContribution: def.scoreContribution,
    severity: def.severity,
    category: def.category,
    reason: def.reason
  };
}

// Levenshtein edit distance (for typosquatting detection).
export function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...new Array(n).fill(0)]);
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost);
    }
  }
  return dp[m][n];
}

// Normalize common leet-speak substitutions used in typosquatting.
export function deleet(str) {
  return str
    .replace(/0/g, 'o')
    .replace(/1/g, 'l')
    .replace(/3/g, 'e')
    .replace(/4/g, 'a')
    .replace(/5/g, 's')
    .replace(/7/g, 't')
    .replace(/\$/g, 's')
    .replace(/@/g, 'a');
}

const URL_REGEX = /((?:https?:\/\/|www\.)[^\s<>"'()]+|(?<![@\w])[a-z0-9-]+(?:\.[a-z0-9-]+)+(?:\/[^\s<>"'()]*)?)/gi;

// Extract candidate URLs / domains from free text.
export function extractUrls(text) {
  if (!text) return [];
  const matches = text.match(URL_REGEX) || [];
  const seen = new Set();
  const urls = [];
  for (let m of matches) {
    m = m.replace(/[.,;:!?)]+$/, ''); // strip trailing punctuation
    const lower = m.toLowerCase();
    // ignore bare tokens whose last label is not a plausible TLD
    const last = lower.split('/')[0].split('.').pop();
    if (!/^[a-z]{2,24}$/.test(last)) continue;
    if (!seen.has(lower)) { seen.add(lower); urls.push(m); }
  }
  return urls;
}

// Best-effort URL parse; prepends a scheme when missing. Returns null on failure.
export function safeParseUrl(raw) {
  if (!raw || typeof raw !== 'string') return null;
  let candidate = raw.trim();
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) candidate = 'http://' + candidate;
  try {
    return new URL(candidate);
  } catch {
    return null;
  }
}
