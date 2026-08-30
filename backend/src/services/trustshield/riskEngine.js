import { THRESHOLDS, RECOMMENDED_ACTIONS } from './constants.js';

function classify(score) {
  if (score <= THRESHOLDS.SAFE_MAX) return 'SAFE';
  if (score <= THRESHOLDS.SUSPICIOUS_MAX) return 'SUSPICIOUS';
  return 'HIGH_RISK';
}

const SEVERITY_RANK = { HIGH: 3, MEDIUM: 2, LOW: 1 };

// Dedupe by code, keeping the highest-contribution instance of each signal.
function dedupe(signals) {
  const byCode = new Map();
  for (const s of signals) {
    const existing = byCode.get(s.code);
    if (!existing || s.scoreContribution > existing.scoreContribution) byCode.set(s.code, s);
  }
  return [...byCode.values()];
}

function pickThreatCategory(signals, score) {
  if (!signals.length || score === 0) return 'NONE';
  const sorted = [...signals].sort((a, b) =>
    b.scoreContribution - a.scoreContribution ||
    SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  return sorted[0].category || 'SUSPICIOUS_CONTENT';
}

function joinReasons(reasons) {
  if (reasons.length === 1) return reasons[0];
  if (reasons.length === 2) return `${reasons[0]} and ${reasons[1]}`;
  return `${reasons.slice(0, -1).join(', ')}, and ${reasons[reasons.length - 1]}`;
}

function buildExplanation(inputType, classification, score, signals) {
  const noun = { url: 'link', email: 'email', message: 'message', qr: 'QR code' }[inputType] || 'interaction';
  if (classification === 'SAFE' || !signals.length || score === 0) {
    return `No significant risk indicators were detected in this ${noun}. It appears safe based on our automated checks — but always stay alert and never share OTPs, passwords, or payment details on unexpected requests.`;
  }
  const top = [...signals]
    .sort((a, b) => b.scoreContribution - a.scoreContribution)
    .slice(0, 4)
    .map(s => s.reason || s.name.toLowerCase());
  return `This ${noun} was classified as ${classification} with a risk score of ${score}/100. It was flagged because it ${joinReasons(top)}.`;
}

// Turn a list of internal signals into the stable TrustShield result contract.
export function buildResult(inputType, rawSignals) {
  const signals = dedupe(rawSignals);
  const total = signals.reduce((sum, s) => sum + s.scoreContribution, 0);
  const riskScore = Math.max(0, Math.min(100, total));
  const classification = classify(riskScore);
  // A SAFE result never carries a threat category — avoids alarming false positives.
  const threatCategory = classification === 'SAFE' ? 'NONE' : pickThreatCategory(signals, riskScore);
  const explanation = buildExplanation(inputType, classification, riskScore, signals);
  const recommendedAction = RECOMMENDED_ACTIONS[classification];

  return {
    riskScore,
    classification,
    threatCategory,
    signals: signals.map(({ code, name, description, scoreContribution, severity }) =>
      ({ code, name, description, scoreContribution, severity })),
    explanation,
    recommendedAction
  };
}
