import { useState, useRef, useEffect, useCallback } from 'react';
import { ShieldAlert, Play, Loader2, AlertTriangle, ShieldCheck, Info, ArrowRight, Trash2, Lock } from 'lucide-react';
import { apiPost, apiGet, apiDelete } from '../lib/api';
import { PageHeader, ErrorBanner } from '../components/ui';

const LEVEL_COLORS = {
  'Low observed risk': '#34d399', 'Suspicious': '#fbbf24', 'High risk': '#f87171',
  'Known malicious': '#ef4444', 'Inconclusive': '#94a3b8', 'Analysis failed': '#94a3b8',
};
const SOURCE_LABEL = { observed: 'Observed', reputation: 'Reputation', rule: 'Rule', heuristic: 'Heuristic' };

export default function ThreatSandbox() {
  const [url, setUrl] = useState('');
  const [job, setJob] = useState(null);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const pollRef = useRef(null);

  const stopPolling = () => { if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; } };
  useEffect(() => stopPolling, []);

  const loadReport = useCallback(async (id) => {
    try { setReport(await apiGet(`/sandbox/jobs/${id}/report`)); }
    catch (e) { setError(e.message); }
  }, []);

  async function start(e) {
    e.preventDefault();
    setError(''); setReport(null); setJob(null);
    if (!url.trim()) { setError('Please enter a URL to analyze.'); return; }
    setBusy(true);
    try {
      const created = await apiPost('/sandbox/jobs', { url: url.trim() });
      setJob({ status: created.status, id: created.id, isolationMode: created.isolationMode, notice: created.notice });
      pollRef.current = setInterval(async () => {
        try {
          const j = await apiGet(`/sandbox/jobs/${created.id}`);
          setJob(prev => ({ ...prev, ...j }));
          if (j.status === 'completed') { stopPolling(); setBusy(false); loadReport(created.id); }
          else if (j.status === 'failed' || j.status === 'expired') { stopPolling(); setBusy(false); }
        } catch (err) { stopPolling(); setBusy(false); setError(err.message); }
      }, 1000);
    } catch (err) {
      setBusy(false);
      setError(err.message || 'Unable to start analysis.');
    }
  }

  async function remove() {
    if (!job?.id) return;
    try { await apiDelete(`/sandbox/jobs/${job.id}`); } catch { /* ignore */ }
    stopPolling(); setJob(null); setReport(null); setBusy(false);
  }

  const level = report?.riskLevel || job?.riskLevel;
  const levelColor = LEVEL_COLORS[level] || '#94a3b8';

  return (
    <div>
      <PageHeader icon={ShieldAlert} title="Threat Sandbox"
        subtitle="Submit a suspicious URL for isolated inspection. The link is never opened in your browser — a disposable worker analyzes it and returns explainable evidence." />

      {/* Safety / consent notice */}
      <div className="ts-card ts-card-pad" data-testid="sandbox-notice"
        style={{ marginBottom: 16, borderColor: 'rgba(251,191,36,0.35)', background: 'rgba(251,191,36,0.06)' }}>
        <div style={{ display: 'flex', gap: 10 }}>
          <Lock size={18} color="#fbbf24" style={{ flexShrink: 0, marginTop: 2 }} />
          <div style={{ fontSize: 13.5, color: 'var(--ts-muted)', lineHeight: 1.55 }}>
            <strong style={{ color: '#fbbf24' }}>Development / reduced-isolation mode.</strong> Process separation is
            <em> not</em> equivalent to container isolation. Live browsing of arbitrary public URLs is disabled by default
            in this preview — such URLs receive static + reputation analysis only. Do not submit URLs containing personal
            tokens; sensitive query parameters are redacted before storage.
          </div>
        </div>
      </div>

      <form onSubmit={start} className="ts-card ts-card-pad" data-testid="sandbox-form">
        <label className="ts-label" htmlFor="sandbox-url">Suspicious URL</label>
        <input id="sandbox-url" data-testid="sandbox-url-input" className="ts-input ts-mono"
          placeholder="https://suspicious-example.com/verify" value={url} onChange={e => setUrl(e.target.value)}
          autoComplete="off" spellCheck="false" disabled={busy} />
        <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
          <button type="submit" className="ts-btn ts-btn-primary" data-testid="sandbox-submit" disabled={busy}>
            {busy ? <Loader2 size={18} className="ts-spin" /> : <Play size={18} />} {busy ? 'Analyzing…' : 'Start Analysis'}
          </button>
          {job && <button type="button" className="ts-btn ts-btn-danger" data-testid="sandbox-delete" onClick={remove}>
            <Trash2 size={16} /> Discard
          </button>}
        </div>
      </form>

      <div style={{ marginTop: 18, display: 'grid', gap: 14 }}>
        <ErrorBanner message={error} />

        {/* Progress */}
        {job && !report && (
          <div className="ts-card ts-card-pad ts-fade-in" data-testid="sandbox-progress">
            <ProgressSteps status={job.status} />
            {job.status === 'failed' && (
              <p data-testid="sandbox-failed" style={{ color: '#fca5a5', marginTop: 12 }}>
                <AlertTriangle size={15} /> Analysis failed / blocked: {job.error || 'unknown reason'}
              </p>
            )}
          </div>
        )}

        {/* Report */}
        {report && (
          <div className="ts-card ts-fade-in" data-testid="sandbox-report" style={{ overflow: 'hidden', borderColor: levelColor + '55' }}>
            <div style={{ padding: '22px 24px', display: 'flex', gap: 22, alignItems: 'center', flexWrap: 'wrap',
              background: `linear-gradient(90deg, ${levelColor}22, transparent)` }}>
              <div style={{ textAlign: 'center' }}>
                <div className="ts-mono" data-testid="sandbox-score" style={{ fontSize: 46, fontWeight: 700, color: levelColor, lineHeight: 1 }}>{report.riskScore}</div>
                <div className="ts-mono" style={{ fontSize: 12, color: 'var(--ts-muted)' }}>/ 100</div>
              </div>
              <div style={{ flex: 1, minWidth: 220 }}>
                <span className="ts-chip" data-testid="sandbox-level" style={{ color: levelColor, borderColor: levelColor + '66' }}>{level}</span>
                <div style={{ marginTop: 10, fontSize: 13.5, color: 'var(--ts-muted)' }}>
                  Confidence: <strong style={{ color: 'var(--ts-text)' }} data-testid="sandbox-confidence">{report.confidence}</strong>
                  <span style={{ marginLeft: 6 }}>({report.confidenceBasis})</span>
                </div>
                <div style={{ marginTop: 4, fontSize: 12.5, color: 'var(--ts-muted)' }}>
                  Analysis v{report.analysisVersion} · {report.isolationMode}
                </div>
              </div>
            </div>

            {/* Screenshot */}
            {report.observed?.screenshotAvailable && (
              <div style={{ padding: '16px 24px', borderTop: '1px solid var(--ts-border)' }}>
                <span className="ts-label">Final-page screenshot (rendered in isolation)</span>
                <img data-testid="sandbox-screenshot" alt="Sandbox screenshot of final page"
                  src={`${(import.meta.env.VITE_API_URL || '').replace(/\/$/, '')}/api/sandbox/jobs/${job.id}/screenshot`}
                  style={{ maxWidth: '100%', borderRadius: 10, border: '1px solid var(--ts-border)', marginTop: 6 }} />
              </div>
            )}

            {/* Evidence cards */}
            <Section title="Evidence & findings" testid="sandbox-findings">
              {report.findings.length === 0
                ? <p style={{ color: 'var(--ts-muted)', margin: 0 }}>No risk signals were observed. This is not proof of safety.</p>
                : <div style={{ display: 'grid', gap: 10 }}>
                    {report.findings.map((f, i) => (
                      <div key={f.code + i} data-testid={`finding-${f.code}`} style={{ padding: '13px 15px', borderRadius: 12,
                        background: 'rgba(120,160,210,0.05)', border: '1px solid var(--ts-border)' }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', alignItems: 'baseline' }}>
                          <strong style={{ fontSize: 14.5 }}>{f.title}</strong>
                          <span style={{ display: 'flex', gap: 6 }}>
                            <span className="ts-chip" style={{ fontSize: 10.5, padding: '2px 8px' }}>{SOURCE_LABEL[f.source] || f.source}</span>
                            <span className="ts-mono" style={{ fontSize: 12, color: levelColor }}>+{f.weight}</span>
                          </span>
                        </div>
                        <p style={{ margin: '6px 0 0', fontSize: 13, color: 'var(--ts-muted)' }}>Evidence: {f.evidence}</p>
                        <p style={{ margin: '3px 0 0', fontSize: 12.5, color: 'var(--ts-muted)' }}>Why it matters: {f.whyItMatters}</p>
                        <p style={{ margin: '3px 0 0', fontSize: 12.5, color: 'var(--ts-muted)' }}>Consequence: {f.consequence}</p>
                        <p style={{ margin: '3px 0 0', fontSize: 12.5, color: 'var(--ts-text)' }}>→ {f.recommendation}</p>
                      </div>
                    ))}
                  </div>}
            </Section>

            {/* Redirect chain */}
            {report.observed?.redirectChain?.length > 0 && (
              <Section title="Redirect chain" testid="sandbox-redirects">
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, alignItems: 'center' }}>
                  {report.observed.redirectChain.map((r, i) => (
                    <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <code className="ts-mono" style={{ fontSize: 12, wordBreak: 'break-all' }}>{r.url} <span style={{ color: 'var(--ts-muted)' }}>({r.status})</span></code>
                      {i < report.observed.redirectChain.length - 1 && <ArrowRight size={13} color="var(--ts-muted)" />}
                    </span>
                  ))}
                </div>
              </Section>
            )}

            {/* Technical details */}
            <Section title="Technical details" testid="sandbox-technical">
              <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '6px 16px', margin: 0, fontSize: 13 }}>
                <Detail k="Final URL" v={report.observed?.finalUrl} mono />
                <Detail k="Final domain" v={report.observed?.finalDomain} mono />
                <Detail k="HTTP status" v={report.observed?.httpStatus} />
                <Detail k="TLS valid" v={report.observed?.tls ? String(report.observed.tls.valid) : 'n/a'} />
                <Detail k="Missing sec. headers" v={report.observed?.securityHeaders?.missing?.join(', ') || 'n/a'} />
                <Detail k="Dynamic performed" v={String(report.observed?.dynamicPerformed)} />
                <Detail k="Worker status" v={report.observed?.workerStatus} />
                <Detail k="Duration (ms)" v={report.observed?.durationMs} />
              </dl>
            </Section>

            {/* Not collected + data sources + limitations */}
            <Section title="Data sources & limitations" testid="sandbox-limits">
              <p style={{ fontSize: 13, margin: '0 0 8px' }}><strong>Sources:</strong> {report.dataSources.map(s => s.name).join(', ')}</p>
              {report.evidenceNotCollected?.length > 0 &&
                <p style={{ fontSize: 13, margin: '0 0 8px', color: 'var(--ts-muted)' }}><strong>Not collected:</strong> {report.evidenceNotCollected.join('; ')}</p>}
              <ul style={{ margin: 0, paddingLeft: 18, fontSize: 12.5, color: 'var(--ts-muted)' }}>
                {report.limitations.map((l, i) => <li key={i} style={{ marginBottom: 3 }}>{l}</li>)}
              </ul>
            </Section>
          </div>
        )}
      </div>
    </div>
  );
}

function ProgressSteps({ status }) {
  const steps = ['queued', 'validating', 'analyzing', 'completed'];
  const idx = steps.indexOf(status === 'failed' ? 'analyzing' : status);
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
      {steps.map((s, i) => (
        <span key={s} className="ts-chip" style={{
          color: i <= idx ? '#22d3ee' : 'var(--ts-muted)',
          borderColor: i <= idx ? 'rgba(34,211,238,0.5)' : 'var(--ts-border)',
        }}>
          {i === idx && status !== 'completed' ? <Loader2 size={13} className="ts-spin" /> : <Info size={13} />} {s}
        </span>
      ))}
    </div>
  );
}

function Section({ title, testid, children }) {
  return (
    <div style={{ padding: '18px 24px', borderTop: '1px solid var(--ts-border)' }} data-testid={testid}>
      <h3 style={{ margin: '0 0 12px', fontSize: 13, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--ts-muted)' }}>{title}</h3>
      {children}
    </div>
  );
}

function Detail({ k, v, mono }) {
  return (<>
    <dt style={{ color: 'var(--ts-muted)' }}>{k}</dt>
    <dd className={mono ? 'ts-mono' : ''} style={{ margin: 0, wordBreak: 'break-all' }}>{v ?? 'n/a'}</dd>
  </>);
}
