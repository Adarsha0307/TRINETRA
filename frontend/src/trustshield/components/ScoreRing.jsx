import { classificationMeta } from '../lib/risk';

// Circular gauge showing the 0-100 risk score, colored by classification.
export default function ScoreRing({ score = 0, classification, size = 150 }) {
  const meta = classificationMeta(classification);
  const stroke = 11;
  const r = (size - stroke) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.max(0, Math.min(100, score)) / 100;
  const offset = circ * (1 - pct);
  return (
    <div style={{ position: 'relative', width: size, height: size }} data-testid="score-ring">
      <svg width={size} height={size} style={{ transform: 'rotate(-90deg)' }}>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgba(120,160,210,0.15)" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={meta.color} strokeWidth={stroke}
          strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset .8s cubic-bezier(.2,.8,.2,1)', filter: `drop-shadow(0 0 8px ${meta.glow})` }} />
      </svg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
        <span className="ts-mono" data-testid="score-value" style={{ fontSize: size * 0.3, fontWeight: 700, lineHeight: 1, color: meta.color }}>{score}</span>
        <span className="ts-mono" style={{ fontSize: 12, color: 'var(--ts-muted)' }}>/ 100</span>
      </div>
    </div>
  );
}
