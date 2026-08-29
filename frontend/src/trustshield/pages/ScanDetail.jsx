import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import { apiGet } from '../lib/api';
import RiskResult from '../components/RiskResult';
import { Loader, ErrorBanner } from '../components/ui';
import { prettyType, formatDate } from '../lib/risk';

export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiGet(`/scans/${id}`)
      .then(setScan)
      .catch(err => setError(err.message || 'Scan not found.'))
      .finally(() => setLoading(false));
  }, [id]);

  return (
    <div>
      <button onClick={() => navigate('/history')} className="ts-btn ts-btn-ghost" data-testid="back-to-history"
        style={{ marginBottom: 18 }}>
        <ArrowLeft size={17} /> Back to history
      </button>
      {loading && <Loader label="Loading scan…" />}
      <ErrorBanner message={error} />
      {!loading && scan && (
        <>
          <p style={{ color: 'var(--ts-muted)', marginBottom: 14 }}>
            {prettyType(scan.inputType)} scan · {formatDate(scan.createdAt)}
            {scan.inputPreview ? <> · <span className="ts-mono">{scan.inputPreview}</span></> : null}
          </p>
          <RiskResult result={scan} />
        </>
      )}
    </div>
  );
}
