-- TrustShield fraud-detection scan storage (no authentication in MVP).

CREATE TABLE IF NOT EXISTS scans (
  id                 SERIAL PRIMARY KEY,
  input_type         TEXT NOT NULL CHECK (input_type IN ('url','email','message','qr')),
  input_preview      TEXT,
  risk_score         INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  classification     TEXT NOT NULL CHECK (classification IN ('SAFE','SUSPICIOUS','HIGH_RISK')),
  threat_category    TEXT NOT NULL,
  explanation        TEXT NOT NULL,
  recommended_action TEXT NOT NULL,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_input_type ON scans(input_type);
CREATE INDEX IF NOT EXISTS idx_scans_classification ON scans(classification);

CREATE TABLE IF NOT EXISTS scan_signals (
  id                 SERIAL PRIMARY KEY,
  scan_id            INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  signal_code        TEXT NOT NULL,
  signal_name        TEXT NOT NULL,
  description        TEXT NOT NULL,
  score_contribution INTEGER NOT NULL,
  severity           TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH'))
);

CREATE INDEX IF NOT EXISTS idx_scan_signals_scan_id ON scan_signals(scan_id);
