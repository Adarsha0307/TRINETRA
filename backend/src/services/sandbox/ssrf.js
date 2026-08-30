import net from 'net';
import dns from 'dns/promises';

// ---------------------------------------------------------------------------
// SSRF protection. Classifies IPs and validates that a destination never
// resolves into a blocked network. Revalidate on EVERY request and redirect.
// ---------------------------------------------------------------------------

export class SsrfError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'SsrfError';
    this.code = code || 'SSRF_BLOCKED';
    this.status = 400;
  }
}

// --- IPv4 helpers ---------------------------------------------------------
function ipv4ToLong(ip) {
  const parts = ip.split('.').map(Number);
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}
function inV4(ip, cidr) {
  const [range, bitsStr] = cidr.split('/');
  const bits = parseInt(bitsStr, 10);
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (ipv4ToLong(ip) & mask) === (ipv4ToLong(range) & mask);
}

// Blocked IPv4 ranges: loopback, private, link-local (+ cloud metadata),
// CGNAT, reserved, multicast, broadcast, "this network".
const BLOCKED_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24',
  '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4', '255.255.255.255/32',
];
const CLOUD_METADATA_V4 = ['169.254.169.254', '100.100.100.200'];

function classifyV4(ip) {
  if (CLOUD_METADATA_V4.includes(ip)) return { blocked: true, reason: 'cloud metadata endpoint', code: 'BLOCKED_METADATA' };
  for (const cidr of BLOCKED_V4) {
    if (inV4(ip, cidr)) return { blocked: true, reason: `blocked IPv4 range ${cidr}`, code: 'BLOCKED_RANGE' };
  }
  return { blocked: false };
}

// --- IPv6 helpers ---------------------------------------------------------
function classifyV6(ip) {
  const a = ip.toLowerCase().replace(/^\[|\]$/g, '');
  if (a === '::1' || a === '::') return { blocked: true, reason: 'IPv6 loopback/unspecified', code: 'BLOCKED_LOOPBACK' };
  if (a.startsWith('fe80')) return { blocked: true, reason: 'IPv6 link-local (fe80::/10)', code: 'BLOCKED_LINK_LOCAL' };
  if (a.startsWith('fc') || a.startsWith('fd')) return { blocked: true, reason: 'IPv6 unique-local (fc00::/7)', code: 'BLOCKED_ULA' };
  if (a.startsWith('ff')) return { blocked: true, reason: 'IPv6 multicast (ff00::/8)', code: 'BLOCKED_MULTICAST' };
  // IPv4-mapped IPv6 (::ffff:a.b.c.d) — classify the embedded v4.
  const mapped = a.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return classifyV4(mapped[1]);
  const mapped2 = a.match(/::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/);
  if (mapped2) {
    const hi = parseInt(mapped2[1], 16), lo = parseInt(mapped2[2], 16);
    const v4 = `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    return classifyV4(v4);
  }
  return { blocked: false };
}

export function classifyIp(ip) {
  const type = net.isIP(ip);
  if (type === 4) return classifyV4(ip);
  if (type === 6) return classifyV6(ip);
  return { blocked: true, reason: 'not a valid IP', code: 'INVALID_IP' };
}

// Detect alternate/obfuscated IP encodings in a hostname (decimal, octal, hex).
export function normalizeHostIp(host) {
  const h = host.replace(/^\[|\]$/g, '').toLowerCase();
  if (net.isIP(h)) return h;
  // Pure decimal, e.g. 2130706433 => 127.0.0.1
  if (/^\d+$/.test(h)) {
    const n = Number(h);
    if (n >= 0 && n <= 4294967295) {
      return `${(n >>> 24) & 255}.${(n >>> 16) & 255}.${(n >>> 8) & 255}.${n & 255}`;
    }
  }
  // Hex (0x7f000001) or octal/hex dotted parts => reconstruct.
  if (/^(0x[0-9a-f]+|0\d+|\d+)(\.(0x[0-9a-f]+|0\d+|\d+)){0,3}$/.test(h) && /[0x]/.test(h)) {
    const parts = h.split('.').map(p => {
      if (p.startsWith('0x')) return parseInt(p, 16);
      if (/^0\d+$/.test(p)) return parseInt(p, 8);
      return parseInt(p, 10);
    });
    if (parts.every(p => Number.isFinite(p) && p >= 0 && p <= 255) && parts.length === 4) {
      return parts.join('.');
    }
  }
  return null; // not an IP literal — treat as a DNS name
}

// Validate a destination URL. Resolves DNS and checks EVERY resolved address.
// Returns { url, hostname, addresses[] } or throws SsrfError.
export async function assertDestinationAllowed(rawUrl, { resolver } = {}) {
  let url;
  try { url = new URL(rawUrl); } catch { throw new SsrfError('Malformed URL', 'MALFORMED'); }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new SsrfError(`Unsupported protocol "${url.protocol}"`, 'BLOCKED_PROTOCOL');
  }
  if (url.username || url.password) {
    throw new SsrfError('Embedded credentials are not allowed in the URL', 'BLOCKED_CREDENTIALS');
  }

  const host = url.hostname.toLowerCase();
  if (!host) throw new SsrfError('Missing hostname', 'MALFORMED');
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) {
    throw new SsrfError(`Blocked internal hostname "${host}"`, 'BLOCKED_INTERNAL');
  }

  // IP literal (including obfuscated encodings) — classify directly.
  const ipLiteral = normalizeHostIp(host);
  if (ipLiteral) {
    const c = classifyIp(ipLiteral);
    if (c.blocked) throw new SsrfError(`Blocked address ${ipLiteral}: ${c.reason}`, c.code);
    return { url: url.href, hostname: host, addresses: [ipLiteral] };
  }

  // DNS name — resolve and check ALL addresses (defends DNS rebinding).
  let records;
  try {
    records = resolver ? await resolver(host) : await dns.lookup(host, { all: true });
  } catch (err) {
    throw new SsrfError(`DNS resolution failed for "${host}"`, 'DNS_FAILED');
  }
  const addresses = records.map(r => r.address);
  if (addresses.length === 0) throw new SsrfError(`No addresses for "${host}"`, 'DNS_EMPTY');
  for (const addr of addresses) {
    const c = classifyIp(addr);
    if (c.blocked) throw new SsrfError(`"${host}" resolves to blocked address ${addr}: ${c.reason}`, c.code);
  }
  return { url: url.href, hostname: host, addresses };
}
