import { useState } from 'react';
import { Link2, ShieldCheck } from 'lucide-react';
import { apiPost } from '../lib/api';
import RiskResult from '../components/RiskResult';
import { Loader, ErrorBanner, PageHeader } from '../components/ui';

export default function UrlScanner() {
  const [url, setUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(''); setResult(null);
    if (!url.trim()) { setError('Please enter a URL to analyze.'); return; }
    setLoading(true);
    try {
      const data = await apiPost('/scan/url', { url: url.trim() });
      setResult(data);
    } catch (err) {
      setError(err.message || 'Unable to analyze this URL. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div>
      <PageHeader icon={Link2} title="URL Scanner"
        subtitle="Check whether a link is safe before you click. TrustShield inspects the URL structure and never opens the link." />
      <form onSubmit={submit} className="ts-card ts-card-pad" data-testid="url-form">
        <label className="ts-label" htmlFor="url-input">URL or domain</label>
        <input id="url-input" data-testid="url-input" className="ts-input ts-mono"
          placeholder="https://example.com/login" value={url} onChange={e => setUrl(e.target.value)}
          autoComplete="off" spellCheck="false" />
        <button type="submit" className="ts-btn ts-btn-primary" data-testid="url-submit"
          disabled={loading} style={{ marginTop: 16 }}>
          <ShieldCheck size={18} /> {loading ? 'Analyzing…' : 'Analyze URL'}
        </button>
      </form>
      <div style={{ marginTop: 18, display: 'grid', gap: 14 }}>
        <ErrorBanner message={error} />
        {loading && <Loader />}
        {!loading && result && <RiskResult result={result} />}
      </div>
    </div>
  );
}
