# TrustShield — Part 1 (Backend) Handoff

AI-powered digital fraud detection. Part 1 delivers the **rule-based detection engine**,
scan APIs, PostgreSQL persistence and dashboard data. **No authentication** in the MVP
(intentionally deferred — existing auth code is left untouched and simply not required by
the scan endpoints).

## Stack
Node.js + Express + PostgreSQL (existing `nexnetra` repo, extended — nothing rebuilt).

## Setup & Run
```bash
# 1. PostgreSQL running with a database named `nexnetra`
# 2. Root .env (see .env.example) — key vars:
#    DATABASE_URL=postgresql://postgres:postgres@127.0.0.1:5432/nexnetra
#    JWT_SECRET=<32+ chars>   (still required by server bootstrap; auth deferred)
#    PORT=4000
npm run migrate            # applies migrations (incl. 002_trustshield_scans.sql)
npm run start --workspace backend   # or: node backend/src/server.js
# Health: GET http://localhost:4000/api/health
```

## Scan Result Contract (STABLE — frontend depends on it)
```json
{
  "id": 1,
  "createdAt": "2026-...Z",
  "riskScore": 92,
  "classification": "SAFE | SUSPICIOUS | HIGH_RISK",
  "threatCategory": "PHISHING",
  "signals": [
    { "code": "BRAND_IMPERSONATION", "name": "Brand impersonation",
      "description": "...", "scoreContribution": 20, "severity": "HIGH" }
  ],
  "explanation": "This ... was classified as ...",
  "recommendedAction": "..."
}
```
Thresholds: `0–29 SAFE`, `30–69 SUSPICIOUS`, `70–100 HIGH_RISK` (in `constants.js`).
Threat categories: PHISHING, IMPERSONATION, OTP_SCAM, BANKING_SCAM, PAYMENT_SCAM,
JOB_SCAM, INVESTMENT_SCAM, LOAN_SCAM, REWARD_SCAM, MALICIOUS_URL, SUSPICIOUS_CONTENT, NONE.

## Endpoints (all under `/api`, no auth)
| Method | Path | Body |
|---|---|---|
| POST | `/api/scan/url` | `{ "url": "http://..." }` |
| POST | `/api/scan/email` | `{ "sender"?, "subject"?, "content" }` |
| POST | `/api/scan/message` | `{ "content" }` (also accepts `message`/`text`) |
| POST | `/api/scan/qr` | multipart field `image` (≤2MB) **or** `{ "content": "<decoded>" }` |
| GET | `/api/scans?limit=&offset=` | list (summary) |
| GET | `/api/scans/:id` | full scan + signals |
| DELETE | `/api/scans/:id` | 204 |
| GET | `/api/dashboard` | totals, breakdowns, recent scans (real DB data) |

Scan POSTs return `201`; invalid input returns `400`; missing scan `404`.

## Database (migration `002_trustshield_scans.sql`)
- `scans` (id, input_type, input_preview, risk_score, classification, threat_category,
  explanation, recommended_action, created_at) — CHECK constraints + indexes.
- `scan_signals` (id, scan_id FK→scans ON DELETE CASCADE, signal_code, signal_name,
  description, score_contribution, severity).
All writes use parameterized SQL. Raw email/message content is **not** stored
(`input_preview` holds only a non-sensitive hint like a sender/host domain, or null).

## Code map (`backend/src/services/trustshield/`)
- `constants.js` — thresholds, brands, suspicious TLDs, **central signal catalog**.
- `urlAnalyzer.js` — offline URL heuristics (IP host, punycode, `@`-obfuscation, encoding,
  subdomains, credential/payment keywords, suspicious TLD, brand impersonation/typosquatting).
- `contentSignals.js` — shared email/SMS scam detectors; extracts & re-analyzes embedded URLs.
- `emailAnalyzer` / `messageAnalyzer` / `qrContent` (`index.js`), `qrDecode.js` (jimp+jsQR).
- `riskEngine.js` — dedupe → clamp 0–100 → classify → threat category → explanation (built
  ONLY from detected signals) → recommended action.
- `../repositories/scanRepository.js` — persistence & dashboard aggregation.
- Routes: `backend/src/routes/scanRoutes.js`. Tests: `backend/test/trustshield.test.js` (15).

## Security
Helmet, CORS, rate limiting, JSON body limit (1MB), QR upload limit (2MB, images only),
parameterized SQL, centralized error handler, input validation on every endpoint.
**No arbitrary URL fetching** — URL analysis is fully offline (no SSRF surface).

### Deferred safe URL-fetching requirements (for future live checks)
localhost/private-IP/internal-hostname blocking, redirect validation, DNS-rebinding
protection, timeouts, and response-size limits before ever fetching a user-supplied URL.

## Known limitations
- Detection is rule-based (no ML/LLM) — Agent 2 owns the ML service.
- URL analysis is offline; no live reputation/DNS/SSL lookups in the MVP scan flow.
- Authentication deferred: scan endpoints are public.
