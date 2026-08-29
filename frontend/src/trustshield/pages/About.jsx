import { Shield } from 'lucide-react';
import { PageHeader } from '../components/ui';

const FLOW = ['React', 'Express API', 'Detection Engine', 'ML Service', 'Risk Engine', 'PostgreSQL'];

export default function About() {
  return (
    <div>
      <PageHeader icon={Shield} title="About TrustShield"
        subtitle="An explainable, rule-based fraud detection platform augmented with a machine-learning model." />

      <div className="ts-card ts-card-pad" style={{ marginBottom: 16 }}>
        <h3 style={{ marginTop: 0 }}>Architecture</h3>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }} data-testid="architecture-flow">
          {FLOW.map((n, i) => (
            <span key={n} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span className="ts-chip">{n}</span>{i < FLOW.length - 1 && <span style={{ color: 'var(--ts-muted)' }}>→</span>}
            </span>
          ))}
        </div>
        <p style={{ color: 'var(--ts-muted)', fontSize: 14, marginBottom: 0, marginTop: 16, lineHeight: 1.6 }}>
          The browser talks only to the Node/Express API. Express runs the rule-based detection engine,
          consults a Python ML service for a phishing-likelihood score on URLs, combines everything in a
          transparent risk engine, and persists results in PostgreSQL.
        </p>
      </div>

      <div className="ts-card ts-card-pad" style={{ marginBottom: 16 }}>
        <h3 style={{ marginTop: 0 }}>How scoring works</h3>
        <p style={{ color: 'var(--ts-muted)', fontSize: 14, lineHeight: 1.6 }}>
          Each detected signal contributes points to a 0–100 risk score. The classification thresholds are:
        </p>
        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
          <span className="ts-chip" style={{ color: '#34d399', borderColor: 'rgba(52,211,153,0.4)' }}>0–29 · Safe</span>
          <span className="ts-chip" style={{ color: '#fbbf24', borderColor: 'rgba(251,191,36,0.4)' }}>30–69 · Suspicious</span>
          <span className="ts-chip" style={{ color: '#f87171', borderColor: 'rgba(248,113,113,0.4)' }}>70–100 · High Risk</span>
        </div>
      </div>

      <div className="ts-card ts-card-pad">
        <h3 style={{ marginTop: 0 }}>ML baseline model</h3>
        <p style={{ color: 'var(--ts-muted)', fontSize: 14, lineHeight: 1.6, margin: 0 }}>
          A Logistic Regression classifier trained on URL structural features (length, subdomains,
          IP host, punycode, encoded chars, keywords, HTTPS). Evaluated results — accuracy ≈ 0.94,
          precision ≈ 0.93, recall ≈ 0.95, F1 ≈ 0.94. The model supports, but never overrides, the
          explainable rule engine. Detection is not a guarantee — always verify through official channels.
        </p>
      </div>
    </div>
  );
}
