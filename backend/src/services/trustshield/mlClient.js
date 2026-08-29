// Thin client for the TrustShield ML service. Node is the API boundary — the
// browser NEVER calls the ML service directly. Fails open (returns null) so a
// down/slow ML service never breaks a rule-based scan.
const ML_URL = process.env.ML_SERVICE_URL || 'http://127.0.0.1:5001';

export async function predictUrl(features) {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 1500);
    const res = await fetch(`${ML_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ features }),
      signal: controller.signal
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    const data = await res.json();
    if (typeof data.probability !== 'number') return null;
    return { probability: data.probability, modelVersion: data.modelVersion || 'unknown' };
  } catch {
    return null;
  }
}
