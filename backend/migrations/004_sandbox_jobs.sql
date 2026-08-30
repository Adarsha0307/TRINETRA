-- ClickShield Threat Sandbox — asynchronous analysis jobs.
-- Stores only redacted URLs (no raw sensitive URLs/tokens). Reports are JSONB.

CREATE TABLE IF NOT EXISTS sandbox_jobs (
  id                 TEXT PRIMARY KEY,
  status             TEXT NOT NULL CHECK (status IN ('queued','validating','analyzing','completed','failed','expired')),
  original_url       TEXT NOT NULL,      -- redacted for storage
  normalized_url     TEXT NOT NULL,      -- redacted for storage
  host               TEXT,
  correlation_id     TEXT NOT NULL,
  risk_score         INTEGER CHECK (risk_score BETWEEN 0 AND 100),
  risk_level         TEXT,
  confidence         TEXT,
  dynamic_performed  BOOLEAN NOT NULL DEFAULT FALSE,
  report             JSONB,
  screenshot_path    TEXT,
  error              TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at         TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sandbox_jobs_status ON sandbox_jobs(status);
CREATE INDEX IF NOT EXISTS idx_sandbox_jobs_expires_at ON sandbox_jobs(expires_at);
CREATE INDEX IF NOT EXISTS idx_sandbox_jobs_created_at ON sandbox_jobs(created_at DESC);
