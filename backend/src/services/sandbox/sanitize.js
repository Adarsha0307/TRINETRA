// Output sanitization: any string that originated from the target website must
// be neutralized before it is stored or returned to the client. We store plain
// text only (the frontend renders it escaped as well — defense in depth).
const CONTROL_CHARS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g;

export function sanitizeText(value, maxLen = 500) {
  if (value === null || value === undefined) return null;
  let s = String(value).replace(CONTROL_CHARS, '').replace(/\s+/g, ' ').trim();
  if (s.length > maxLen) s = s.slice(0, maxLen) + '…';
  return s;
}

export function sanitizeUrlString(value, maxLen = 2048) {
  if (!value) return null;
  const s = String(value).replace(CONTROL_CHARS, '').trim();
  // Only http/https are ever navigated; neutralize any other scheme label so it
  // can never be interpreted as an executable/link scheme by the client.
  if (!/^https?:\/\//i.test(s)) {
    return sanitizeText(s.replace(/^([a-z][a-z0-9+.-]*):/i, '[$1] '), 200);
  }
  return s.slice(0, maxLen);
}

export function sanitizeStringArray(arr, maxItems = 50, maxLen = 300) {
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, maxItems).map(v => sanitizeText(v, maxLen)).filter(Boolean);
}
