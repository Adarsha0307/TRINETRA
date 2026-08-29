import { AlertTriangle, ShieldCheck, ShieldAlert, Info, ArrowRight } from 'lucide-react';
import ScoreRing from './ScoreRing';
import { classificationMeta, severityMeta, prettyCategory } from '../lib/risk';

const ICONS = { SAFE: ShieldCheck, SUSPICIOUS: ShieldAlert, HIGH_RISK: AlertTriangle };

// Reusable scan result. Renders ONLY the backend-provided signals/explanation.
export default function RiskResult({ result, decodedDestination }) {
  if (!result) return null;
  const meta = classificationMeta(result.classification);
  const Icon = ICONS[result.classification] || Info;
  const signals = result.signals || [];

  return (
    <div className="ts-card ts-fade-in" data-testid="scan-result"
      style={{ overflow: 'hidden', borderColor: meta.ring + '55' }}>
      {/* Header band */}
      <div style={{ padding: '22px 24px', display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap',
        background: `linear-gradient(90deg, ${meta.glow}, transparent)` }}>
        <ScoreRing score={result.riskScore} classification={result.classification} size={132} />
        <div style={{ flex: 1, minWidth: 220 }}>
          <div className="ts-chip" data-testid="result-classification"
            style={{ color: meta.color, borderColor: meta.ring + '66', background: meta.glow }}>
            <Icon size={15} /> {meta.label.toUpperCase()}
          </div>
          <h2 style={{ margin: '12px 0 4px', fontSize: 26, fontWeight: 700, letterSpacing: '-0.02em' }}
            data-testid="result-category">
            {prettyCategory(result.threatCategory)}
          </h2>
          <p style={{ margin: 0, color: 'var(--ts-muted)', fontSize: 14 }}>
            Threat category: <span className="ts-mono" style={{ color: 'var(--ts-text)' }}>{result.threatCategory}</span>
          </p>
        </div>
      </div>

      {decodedDestination && (
        <div style={{ padding: '14px 24px', borderTop: '1px solid var(--ts-border)' }} data-testid="qr-destination">
          <span className="ts-label" style={{ marginBottom: 4 }}>Decoded destination (not opened)</span>
          <code className="ts-mono" style={{ wordBreak: 'break-all', color: 'var(--ts-accent-2)', fontSize: 14 }}>{decodedDestination}</code>
        </div>
      )}

      {/* Why flagged */}
      <div style={{ padding: '20px 24px', borderTop: '1px solid var(--ts-border)' }}>
        <h3 style={{ margin: '0 0 14px', fontSize: 15, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--ts-muted)' }}>
          Why this was flagged
        </h3>
        {signals.length === 0 ? (
          <p style={{ color: 'var(--ts-muted)', margin: 0 }} data-testid="no-signals">
            No risk signals were detected in this scan.
          </p>
        ) : (
          <ul style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: 10 }} data-testid="signal-list">
            {signals.map((s, i) => {
              const sev = severityMeta(s.severity);
              return (
                <li key={s.code + i} data-testid={`signal-${s.code}`}
                  style={{ display: 'flex', gap: 13, padding: '13px 15px', borderRadius: 12,
                    background: 'rgba(120,160,210,0.05)', border: '1px solid var(--ts-border)' }}>
                  <span style={{ width: 8, height: 8, borderRadius: 999, background: sev.color, marginTop: 7, flexShrink: 0,
                    boxShadow: `0 0 8px ${sev.color}` }} />
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'baseline', flexWrap: 'wrap' }}>
                      <strong style={{ fontSize: 14.5 }}>{s.name}</strong>
                      <span style={{ fontSize: 11.5, fontWeight: 700, color: sev.color }}>
                        {sev.label} · +{s.scoreContribution}
                      </span>
                    </div>
                    <p style={{ margin: '4px 0 0', fontSize: 13.5, color: 'var(--ts-muted)', lineHeight: 1.5 }}>{s.description}</p>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
      </div>

      {/* Explanation */}
      <div style={{ padding: '18px 24px', borderTop: '1px solid var(--ts-border)' }}>
        <h3 style={{ margin: '0 0 8px', fontSize: 13, textTransform: 'uppercase', letterSpacing: '.08em', color: 'var(--ts-muted)' }}>Explanation</h3>
        <p style={{ margin: 0, lineHeight: 1.6, fontSize: 15 }} data-testid="result-explanation">{result.explanation}</p>
      </div>

      {/* Recommended action */}
      <div style={{ padding: '18px 24px', borderTop: '1px solid var(--ts-border)',
        background: meta.glow }} data-testid="result-recommendation">
        <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
          <ArrowRight size={18} color={meta.color} style={{ marginTop: 2, flexShrink: 0 }} />
          <div>
            <strong style={{ color: meta.color, fontSize: 14 }}>Recommended action</strong>
            <p style={{ margin: '4px 0 0', lineHeight: 1.6, fontSize: 15 }}>{result.recommendedAction}</p>
          </div>
        </div>
      </div>

      {result.ml && (
        <div style={{ padding: '12px 24px', borderTop: '1px solid var(--ts-border)', fontSize: 12.5, color: 'var(--ts-muted)' }}
          data-testid="ml-info" className="ts-mono">
          ML model {result.ml.modelVersion}: {(result.ml.probability * 100).toFixed(0)}% phishing likelihood
        </div>
      )}
    </div>
  );
}
