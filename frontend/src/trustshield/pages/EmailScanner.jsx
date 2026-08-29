import { useState } from 'react';
import { Mail, ShieldCheck } from 'lucide-react';
import { apiPost } from '../lib/api';
import RiskResult from '../components/RiskResult';
import { Loader, ErrorBanner, PageHeader } from '../components/ui';

export default function EmailScanner() {
  const [sender, setSender] = useState('');
  const [subject, setSubject] = useState('');
  const [content, setContent] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function submit(e) {
    e.preventDefault();
    setError(''); setResult(null);
    if (!content.trim() && !subject.trim()) { setError('Please paste the email content (or at least a subject).'); return; }
    setLoading(true);
    try {
      setResult(await apiPost('/scan/email', { sender: sender.trim(), subject: subject.trim(), content }));
    } catch (err) {
      setError(err.message || 'Unable to analyze this email.');
    } finally { setLoading(false); }
  }

  return (
    <div>
      <PageHeader icon={Mail} title="Email Scanner"
        subtitle="Paste a suspicious email. TrustShield detects phishing tactics and analyzes any links found inside." />
      <form onSubmit={submit} className="ts-card ts-card-pad" data-testid="email-form">
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
          <div>
            <label className="ts-label" htmlFor="email-sender">Sender (optional)</label>
            <input id="email-sender" data-testid="email-sender" className="ts-input"
              placeholder="alerts@bank-support.com" value={sender} onChange={e => setSender(e.target.value)} />
          </div>
          <div>
            <label className="ts-label" htmlFor="email-subject">Subject (optional)</label>
            <input id="email-subject" data-testid="email-subject" className="ts-input"
              placeholder="Urgent: verify your account" value={subject} onChange={e => setSubject(e.target.value)} />
          </div>
        </div>
        <div style={{ marginTop: 14 }}>
          <label className="ts-label" htmlFor="email-content">Email body</label>
          <textarea id="email-content" data-testid="email-content" className="ts-textarea"
            placeholder="Paste the full email content here…" value={content} onChange={e => setContent(e.target.value)} />
        </div>
        <button type="submit" className="ts-btn ts-btn-primary" data-testid="email-submit"
          disabled={loading} style={{ marginTop: 16 }}>
          <ShieldCheck size={18} /> {loading ? 'Analyzing…' : 'Analyze Email'}
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
