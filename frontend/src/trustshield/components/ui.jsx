import { Loader2, AlertCircle } from 'lucide-react';

export function Loader({ label = 'Analyzing…' }) {
  return (
    <div className="ts-card ts-card-pad ts-fade-in" data-testid="loading"
      style={{ display: 'flex', alignItems: 'center', gap: 14, justifyContent: 'center', padding: 40 }}>
      <Loader2 className="ts-spin" size={22} color="#22d3ee" />
      <span style={{ color: 'var(--ts-muted)' }}>{label}</span>
    </div>
  );
}

export function ErrorBanner({ message }) {
  if (!message) return null;
  return (
    <div className="ts-fade-in" data-testid="error-banner" role="alert"
      style={{ display: 'flex', gap: 11, alignItems: 'center', padding: '13px 16px', borderRadius: 12,
        background: 'rgba(248,113,113,0.1)', border: '1px solid rgba(248,113,113,0.35)', color: '#fca5a5' }}>
      <AlertCircle size={18} /> <span style={{ fontSize: 14 }}>{message}</span>
    </div>
  );
}

export function PageHeader({ icon: Icon, title, subtitle }) {
  return (
    <div style={{ marginBottom: 24 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {Icon && <span style={{ display: 'grid', placeItems: 'center', width: 42, height: 42, borderRadius: 12,
          background: 'rgba(34,211,238,0.12)', border: '1px solid rgba(34,211,238,0.3)' }}><Icon size={22} color="#22d3ee" /></span>}
        <h1 style={{ margin: 0, fontSize: 27, fontWeight: 700, letterSpacing: '-0.02em' }}>{title}</h1>
      </div>
      {subtitle && <p style={{ margin: '10px 0 0', color: 'var(--ts-muted)', fontSize: 15, maxWidth: 640 }}>{subtitle}</p>}
    </div>
  );
}
