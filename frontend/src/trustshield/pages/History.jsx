import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { History as HistoryIcon, Trash2, ChevronRight } from 'lucide-react';
import { apiGet, apiDelete } from '../lib/api';
import { ErrorBanner, PageHeader } from '../components/ui';
import { classificationMeta, prettyCategory, prettyType, formatDate } from '../lib/risk';

export default function History() {
  const [scans, setScans] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  function load() {
    setLoading(true);
    apiGet('/scans')
      .then(setScans)
      .catch(err => setError(err.message || 'Unable to load scan history.'))
      .finally(() => setLoading(false));
  }
  useEffect(load, []);

  async function remove(id, e) {
    e.stopPropagation();
    try {
      await apiDelete(`/scans/${id}`);
      setScans(prev => prev.filter(s => s.id !== id));
    } catch (err) {
      setError(err.message || 'Unable to delete scan.');
    }
  }

  return (
    <div>
      <PageHeader icon={HistoryIcon} title="Scan History"
        subtitle="Every scan is stored so you can review past results." />
      <ErrorBanner message={error} />

      {loading ? (
        <div style={{ display: 'grid', gap: 8 }}>{[0, 1, 2, 3].map(i => <div key={i} className="ts-skel" style={{ height: 56 }} />)}</div>
      ) : scans.length === 0 ? (
        <div className="ts-card ts-card-pad" data-testid="history-empty" style={{ textAlign: 'center', color: 'var(--ts-muted)' }}>
          No scans yet. Run a scan from any scanner to build your history.
        </div>
      ) : (
        <div data-testid="history-list" style={{ display: 'grid', gap: 9 }}>
          {scans.map(s => {
            const meta = classificationMeta(s.classification);
            return (
              <div key={s.id} data-testid={`history-row-${s.id}`} onClick={() => navigate(`/history/${s.id}`)}
                className="ts-card" style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 16px', cursor: 'pointer' }}>
                <span className="ts-chip" style={{ fontSize: 11.5, minWidth: 74, justifyContent: 'center' }}>{prettyType(s.inputType)}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14.5, fontWeight: 600 }}>{prettyCategory(s.threatCategory)}</div>
                  <div style={{ fontSize: 12.5, color: 'var(--ts-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {s.inputPreview || '—'} · {formatDate(s.createdAt)}
                  </div>
                </div>
                <span className="ts-mono" style={{ fontWeight: 700, fontSize: 18, color: meta.color }}>{s.riskScore}</span>
                <span className="ts-chip" style={{ fontSize: 11.5, color: meta.color, borderColor: meta.ring + '55' }}>{meta.label}</span>
                <button data-testid={`delete-scan-${s.id}`} onClick={e => remove(s.id, e)} aria-label="Delete scan"
                  className="ts-btn ts-btn-danger" style={{ padding: 9 }}>
                  <Trash2 size={16} />
                </button>
                <ChevronRight size={18} color="var(--ts-muted)" />
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
