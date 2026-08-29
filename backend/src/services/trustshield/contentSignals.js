import { BRANDS } from './constants.js';
import { makeSignal, extractUrls } from './utils.js';
import { analyzeUrlString } from './urlAnalyzer.js';

const DETECTORS = [
  { code: 'URGENCY', re: /(urgent|immediately|right away|act now|as soon as possible|within \d+\s?(hours|minutes|mins|hrs)|expires?\s+(today|soon|in)|final notice|last warning|limited time|hurry)/i },
  { code: 'ACCOUNT_SUSPENSION', re: /(suspend|deactivat|account (is )?(locked|blocked|disabled|restricted)|will be (closed|terminated|deleted)|temporarily (locked|blocked))/i },
  { code: 'THREAT_LANGUAGE', re: /(legal action|lawsuit|penalty|fine|arrest|police|court|prosecut|permanently (closed|banned)|face consequences)/i },
  { code: 'CREDENTIAL_REQUEST', re: /(enter your password|confirm your (identity|account|password|login)|re-?enter your|update your (login|credentials|password)|verify your (login|identity|account details)|username and password)/i },
  { code: 'OTP_REQUEST', re: /(\botp\b|one[-\s]?time (password|code|pin)|verification code|security code|share.{0,15}(code|otp|pin)|do not share.{0,20}(code|otp)|enter.{0,15}(otp|code))/i },
  { code: 'FINANCIAL_REQUEST', re: /(bank account (number|details)|account number|ifsc|routing number|credit card|debit card|\bcvv\b|\bupi\b|net ?banking|card (number|details)|complete your kyc|kyc (update|verification|pending))/i },
  { code: 'PAYMENT_REQUEST', re: /(make a payment|send (money|payment|\$|inr|rs)|wire transfer|processing fee|advance fee|gift card|pay (a )?fee|transfer .{0,15}(amount|money)|bitcoin|crypto|deposit .{0,10}(now|amount))/i },
  { code: 'FAKE_REWARD', re: /(congratulations|you.?ve won|you are (a )?winner|lottery|jackpot|prize|reward|claim your|free gift|voucher|cash prize|lucky draw|gift card worth)/i },
  { code: 'JOB_SCAM', re: /(job offer|work from home|earn (up to )?\$?\d|part[-\s]?time (job|work)|hiring now|daily income|no experience (needed|required)|easy money|earn money (online|daily)|online job)/i },
  { code: 'INVESTMENT_SCAM', re: /(guaranteed returns?|double your (money|investment)|high returns?|risk[-\s]?free (investment|returns?)|investment opportunity|profit daily|\d+%\s*(daily|weekly|monthly|guaranteed)?\s*return|trading signals|crypto profit)/i },
  { code: 'LOAN_SCAM', re: /(instant loan|pre[-\s]?approved loan|low interest loan|loan approved|no collateral|credit limit increase|loan offer|quick loan)/i },
  { code: 'GENERIC_GREETING', re: /(dear (customer|user|member|account holder|sir\/madam|client)|valued customer|dear (sir|madam))/i }
];

const ACTION_RE = /(verify|update|confirm|suspend|reactivat|login|log in|sign in|click|restore|unlock)/i;

// Shared content analysis for emails and SMS/messages.
// Returns internal signals list including signals from any embedded URLs.
export function analyzeContent(text) {
  const signals = [];
  const normalized = (text || '');

  for (const d of DETECTORS) {
    if (d.re.test(normalized)) signals.push(makeSignal(d.code));
  }

  // Brand impersonation in content: brand name + an account action verb.
  const mentionedBrand = BRANDS.find(b => new RegExp(`\\b${b.name}\\b`, 'i').test(normalized));
  if (mentionedBrand && ACTION_RE.test(normalized)) {
    signals.push(makeSignal('BRAND_IMPERSONATION_CONTENT', {
      description: `The content references "${mentionedBrand.name}" while pushing an account action, a common impersonation tactic.`
    }));
  }

  // Extract and analyze embedded URLs; fold their strongest signals in.
  const urls = extractUrls(normalized);
  let worstUrlSignals = [];
  for (const u of urls) {
    const { signals: us, invalid } = analyzeUrlString(u);
    if (invalid) continue;
    const weight = us.reduce((s, x) => s + x.scoreContribution, 0);
    const worstWeight = worstUrlSignals.reduce((s, x) => s + x.scoreContribution, 0);
    if (weight > worstWeight) worstUrlSignals = us;
  }
  if (worstUrlSignals.length) {
    signals.push(makeSignal('SUSPICIOUS_LINK'));
    for (const s of worstUrlSignals) {
      // only add high-value link signals to avoid noise / double counting
      if (s.severity === 'HIGH') signals.push(s);
    }
  }

  return signals;
}
