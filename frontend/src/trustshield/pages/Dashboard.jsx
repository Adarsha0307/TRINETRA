import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { LayoutDashboard, ShieldCheck, ShieldAlert, AlertTriangle, Activity } from 'lucide-react';
import { apiGet } from '../lib/api';
import { ErrorBanner, PageHeader } from '../components/ui';
import { classificationMeta, prettyCategory, prettyType, formatDate } from '../lib/risk';

const STATS = [
  { key: 'totalScans', label: 'Total Scans', icon: Activity, color: '#22d3ee' },
  { key: 'safeScans', label: 'Safe', icon: ShieldCheck, color: '#34d399' },
  { key: 'suspiciousScans', label: 'Suspicious', icon: ShieldAlert, color: '#fbbf24' },
  { key: 'highRiskScans', label: 'High Risk', icon: AlertTriangle, color: '#f87171' },
];

export default function Dashboard() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    apiGet('/dashboard')
      .then(setData)
      .catch(err => setError(err.message || 'Unable to load dashboard.'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <PageHeader icon={LayoutDashboard} title="Dashboard"
        subtitle="Live statistics from every scan TrustShield has analyzed." />
      <ErrorBanner message={error} />

      <div data-testid="stat-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 14 }}>
        {STATS.map(({ key, label, icon: Icon, color }) => (
          <div key={key} className="ts-card ts-card-pad ts-fade-in" data-testid={`stat-${key}`}>
            <Icon size={20} color={color} />
            <div className="ts-mono" style={{ fontSize: 34, fontWeight: 700, marginTop: 10, color }}>
              {loading ? '—' : (data?.[key] ?? 0)}
            </div>
            <div style={{ color: 'var(--ts-muted)', fontSize: 13.5, marginTop: 2 }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.6fr) minmax(0,1fr)', gap: 16, marginTop: 16 }} className="ts-dash-cols">
        {/* Recent scans */}
        <div className="ts-card ts-card-pad">
          <h3 style={{ margin: '0 0 14px', fontSize: 16 }}>Recent Scans</h3>
          {loading ? <SkeletonRows /> : (
            (data?.recentScans?.length ? (
              <div data-testid="recent-scans" style={{ display: 'grid', gap: 8 }}>
                {data.recentScans.map(s => {
                  const meta = classificationMeta(s.classification);
                  return (
                    <button key={s.id} data-testid={`recent-scan-${s.id}`} onClick={() => navigate(`/history/${s.id}`)}
                      style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '11px 13px', borderRadius: 11,
                        background: 'rgba(120,160,210,0.05)', border: '1px solid var(--ts-border)', cursor: 'pointer', textAlign: 'left', width: '100%' }}>
                      <span className="ts-chip" style={{ fontSize: 11 }}>{prettyType(s.inputType)}</span>
                      <span style={{ flex: 1, minWidth: 0, color: 'var(--ts-muted)', fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {s.inputPreview || prettyCategory(s.threatCategory)}
                      </span>
                      <span className="ts-mono" style={{ fontWeight: 700, color: meta.color }}>{s.riskScore}</span>
                      <span style={{ fontSize: 12, color: meta.color, minWidth: 78, textAlign: 'right' }}>{meta.label}</span>
                    </button>
                  );
                })}
              </div>
            ) : <p style={{ color: 'var(--ts-muted)' }} data-testid="recent-empty">No scans yet. Run a scan to see it here.</p>)
          )}
        </div>

        {/* Threat categories */}
        <div className="ts-card ts-card-pad">
          <h3 style={{ margin: '0 0 14px', fontSize: 16 }}>Threat Categories</h3>
          {loading ? <SkeletonRows /> : (
            (data?.threatCategories?.length ? (
              <div data-testid="threat-categories" style={{ display: 'grid', gap: 10 }}>
                {data.threatCategories.map(c => {
                  const total = data.totalScans || 1;
                  const pct = Math.round((c.count / total) * 100);
                  return (
                    <div key={c.category} data-testid={`threat-cat-${c.category}`}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 13, marginBottom: 5 }}>
                        <span>{prettyCategory(c.category)}</span>
                        <span className="ts-mono" style={{ color: 'var(--ts-muted)' }}>{c.count}</span>
                      </div>
                      <div style={{ height: 7, borderRadius: 999, background: 'rgba(120,160,210,0.12)' }}>
                        <div style={{ width: `${pct}%`, height: '100%', borderRadius: 999,
                          background: c.category === 'NONE' ? '#34d399' : 'linear-gradient(90deg,#22d3ee,#a3e635)' }} />
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : <p style={{ color: 'var(--ts-muted)' }}>No data yet.</p>)
          )}
        </div>
      </div>
      <style>{`@media (max-width:860px){.ts-dash-cols{grid-template-columns:1fr !important;}}`}</style>
    </div>
  );
}

function SkeletonRows() {
  return <div style={{ display: 'grid', gap: 8 }}>{[0, 1, 2].map(i => <div key={i} className="ts-skel" style={{ height: 40 }} />)}</div>;
}
