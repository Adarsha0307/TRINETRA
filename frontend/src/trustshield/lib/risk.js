// Shared presentation helpers for risk classification. Never derive risk in the
// UI — always render what the backend returns; these only map to colors/labels.

export const CLASSIFICATION_META = {
  SAFE: { label: 'Safe', color: '#34d399', glow: 'rgba(52,211,153,0.25)', ring: '#34d399' },
  SUSPICIOUS: { label: 'Suspicious', color: '#fbbf24', glow: 'rgba(251,191,36,0.25)', ring: '#fbbf24' },
  HIGH_RISK: { label: 'High Risk', color: '#f87171', glow: 'rgba(248,113,113,0.28)', ring: '#f87171' },
};

export const SEVERITY_META = {
  HIGH: { label: 'High', color: '#f87171' },
  MEDIUM: { label: 'Medium', color: '#fbbf24' },
  LOW: { label: 'Low', color: '#60a5fa' },
};

export function classificationMeta(c) {
  return CLASSIFICATION_META[c] || { label: c || 'Unknown', color: '#94a3b8', glow: 'rgba(148,163,184,0.2)', ring: '#94a3b8' };
}

export function severityMeta(s) {
  return SEVERITY_META[s] || { label: s || '—', color: '#94a3b8' };
}

export function prettyCategory(cat) {
  if (!cat || cat === 'NONE') return 'No threat';
  return cat.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, m => m.toUpperCase());
}

export function prettyType(t) {
  return { url: 'URL', email: 'Email', message: 'Message', qr: 'QR Code' }[t] || t;
}

export function formatDate(iso) {
  if (!iso) return '';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}
