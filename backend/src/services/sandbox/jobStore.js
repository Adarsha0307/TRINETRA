import { query } from '../../utils/db.js';

function mapRow(r) {
  if (!r) return null;
  return {
    id: r.id,
    status: r.status,
    originalUrl: r.original_url,
    normalizedUrl: r.normalized_url,
    host: r.host,
    correlationId: r.correlation_id,
    riskScore: r.risk_score,
    riskLevel: r.risk_level,
    confidence: r.confidence,
    dynamicPerformed: r.dynamic_performed,
    report: r.report,
    screenshotPath: r.screenshot_path,
    error: r.error,
    createdAt: r.created_at,
    updatedAt: r.updated_at,
    expiresAt: r.expires_at,
  };
}

export async function createJob({ id, originalUrlRedacted, normalizedUrlRedacted, host, correlationId, expiresAt }) {
  const { rows } = await query(
    `INSERT INTO sandbox_jobs (id, status, original_url, normalized_url, host, correlation_id, expires_at)
     VALUES ($1,'queued',$2,$3,$4,$5,$6) RETURNING *`,
    [id, originalUrlRedacted, normalizedUrlRedacted, host, correlationId, expiresAt]
  );
  return mapRow(rows[0]);
}

export async function setStatus(id, status, error = null) {
  const { rows } = await query(
    `UPDATE sandbox_jobs SET status=$2, error=$3, updated_at=NOW() WHERE id=$1 RETURNING *`,
    [id, status, error]
  );
  return mapRow(rows[0]);
}

export async function completeJob(id, { report, riskScore, riskLevel, confidence, dynamicPerformed, screenshotPath }) {
  const { rows } = await query(
    `UPDATE sandbox_jobs SET status='completed', report=$2, risk_score=$3, risk_level=$4,
       confidence=$5, dynamic_performed=$6, screenshot_path=$7, updated_at=NOW() WHERE id=$1 RETURNING *`,
    [id, report, riskScore, riskLevel, confidence, dynamicPerformed, screenshotPath]
  );
  return mapRow(rows[0]);
}

export async function getJob(id) {
  const { rows } = await query('SELECT * FROM sandbox_jobs WHERE id=$1', [id]);
  return mapRow(rows[0]);
}

export async function deleteJob(id) {
  const { rowCount } = await query('DELETE FROM sandbox_jobs WHERE id=$1', [id]);
  return rowCount > 0;
}

export async function listRecent(limit = 20) {
  const { rows } = await query(
    `SELECT id,status,host,risk_score,risk_level,confidence,dynamic_performed,created_at,expires_at
     FROM sandbox_jobs ORDER BY created_at DESC LIMIT $1`, [Math.min(limit, 100)]
  );
  return rows.map(r => ({
    id: r.id, status: r.status, host: r.host, riskScore: r.risk_score, riskLevel: r.risk_level,
    confidence: r.confidence, dynamicPerformed: r.dynamic_performed, createdAt: r.created_at, expiresAt: r.expires_at,
  }));
}

// Cleanup: mark past-retention jobs expired and purge their reports/artifacts.
export async function findExpired() {
  const { rows } = await query(
    `SELECT id, screenshot_path FROM sandbox_jobs WHERE expires_at < NOW() AND status <> 'expired'`
  );
  return rows.map(r => ({ id: r.id, screenshotPath: r.screenshot_path }));
}

export async function markExpired(id) {
  await query(
    `UPDATE sandbox_jobs SET status='expired', report=NULL, screenshot_path=NULL, updated_at=NOW() WHERE id=$1`,
    [id]
  );
}
