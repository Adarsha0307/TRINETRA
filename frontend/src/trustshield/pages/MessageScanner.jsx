import { useState } from 'react';
import { MessageSquare, ShieldCheck } from 'lucide-react';
import { apiPost } from '../lib/api';
import RiskResult from '../components/RiskResult';
import { Loader, ErrorBanner, PageHeader } from '../components/ui';

const EXAMPLES = [
  { label: 'Bank / OTP scam', text: 'URGENT: Your account will be suspended today. Verify immediately and share the OTP sent to your phone at http://icici-verify.paypa1.com/login' },
  { label: 'Reward scam', text: 'Congratulations! You have won a $1000 gift card. Claim your prize now: http://claim-reward.xyz/win' },
  { label: 'Normal message', text: 'Hey, are we still on for lunch tomorrow at noon?' },
];

export default function MessageScanner() {
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(''); setResult(null);
    if (!content.trim()) { setError('Please enter a message to analyze.'); return; }
    setLoading(true);
    try {
      setResult(await apiPost('/scan/message', { content }));
    } catch (err) {
      setError(err.message || 'Unable to analyze this message.');
    } finally { setLoading(false); }
  }

  return (
    <div>
      <PageHeader icon={MessageSquare} title="Message / SMS Scanner"
        subtitle="Paste any SMS or chat message. TrustShield detects scam tactics and extracts embedded links for analysis." />
      <form onSubmit={submit} className="ts-card ts-card-pad" data-testid="message-form">
        <label className="ts-label" htmlFor="message-content">Message text</label>
        <textarea id="message-content" data-testid="message-content" className="ts-textarea"
          placeholder="Paste the SMS or message here…" value={content} onChange={e => setContent(e.target.value)} />
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 12 }}>
          {EXAMPLES.map((ex, i) => (
            <button type="button" key={i} className="ts-chip" data-testid={`message-example-${i}`}
              onClick={() => setContent(ex.text)} style={{ cursor: 'pointer', color: 'var(--ts-muted)' }}>
              {ex.label}
            </button>
          ))}
        </div>
        <button type="submit" className="ts-btn ts-btn-primary" data-testid="message-submit"
          disabled={loading} style={{ marginTop: 16 }}>
          <ShieldCheck size={18} /> {loading ? 'Analyzing…' : 'Analyze Message'}
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
