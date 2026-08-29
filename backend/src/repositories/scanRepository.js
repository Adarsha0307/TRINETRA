import { query, getClient } from '../utils/db.js';

// Persist a scan result plus its signals in a single transaction.
export async function saveScan({ inputType, inputPreview, result }) {
  const client = await getClient();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `INSERT INTO scans (input_type, input_preview, risk_score, classification, threat_category, explanation, recommended_action)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id, created_at`,
      [inputType, inputPreview, result.riskScore, result.classification,
       result.threatCategory, result.explanation, result.recommendedAction]
    );
    const scanId = rows[0].id;
    for (const s of result.signals) {
      await client.query(
        `INSERT INTO scan_signals (scan_id, signal_code, signal_name, description, score_contribution, severity)
         VALUES ($1,$2,$3,$4,$5,$6)`,
        [scanId, s.code, s.name, s.description, s.scoreContribution, s.severity]
      );
    }
    await client.query('COMMIT');
    return { id: scanId, createdAt: rows[0].created_at };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

export async function listScans(limit = 50, offset = 0) {
  const { rows } = await query(
    `SELECT id, input_type, input_preview, risk_score, classification, threat_category, created_at
     FROM scans ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
    [Math.min(limit, 200), offset]
  );
  return rows.map(mapScanRow);
}

export async function getScanById(id) {
  const { rows } = await query('SELECT * FROM scans WHERE id = $1', [id]);
  if (!rows.length) return null;
  const { rows: sigRows } = await query(
    'SELECT signal_code, signal_name, description, score_contribution, severity FROM scan_signals WHERE scan_id = $1',
    [id]
  );
  const scan = mapScanRow(rows[0]);
  scan.explanation = rows[0].explanation;
  scan.recommendedAction = rows[0].recommended_action;
  scan.signals = sigRows.map(r => ({
    code: r.signal_code,
    name: r.signal_name,
    description: r.description,
    scoreContribution: r.score_contribution,
    severity: r.severity
  }));
  return scan;
}

export async function deleteScan(id) {
  const { rowCount } = await query('DELETE FROM scans WHERE id = $1', [id]);
  return rowCount > 0;
}

export async function getDashboard() {
  const [{ rows: totals }, { rows: recent }, { rows: categories }, { rows: types }] = await Promise.all([
    query(`SELECT
              COUNT(*)::int AS total,
              COUNT(*) FILTER (WHERE classification = 'SAFE')::int AS safe,
              COUNT(*) FILTER (WHERE classification = 'SUSPICIOUS')::int AS suspicious,
              COUNT(*) FILTER (WHERE classification = 'HIGH_RISK')::int AS high_risk
            FROM scans`),
    query(`SELECT id, input_type, input_preview, risk_score, classification, threat_category, created_at
           FROM scans ORDER BY created_at DESC LIMIT 10`),
    query(`SELECT threat_category, COUNT(*)::int AS count FROM scans
           GROUP BY threat_category ORDER BY count DESC`),
    query(`SELECT input_type, COUNT(*)::int AS count FROM scans GROUP BY input_type`)
  ]);

  const t = totals[0];
  return {
    totalScans: t.total,
    safeScans: t.safe,
    suspiciousScans: t.suspicious,
    highRiskScans: t.high_risk,
    threatCategories: categories.map(c => ({ category: c.threat_category, count: c.count })),
    scansByType: types.map(c => ({ inputType: c.input_type, count: c.count })),
    recentScans: recent.map(mapScanRow)
  };
}

function mapScanRow(r) {
  return {
    id: r.id,
    inputType: r.input_type,
    inputPreview: r.input_preview,
    riskScore: r.risk_score,
    classification: r.classification,
    threatCategory: r.threat_category,
    createdAt: r.created_at
  };
}
