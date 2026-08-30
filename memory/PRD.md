# TrustShield — PRD (Part 1: Backend)

## Problem
AI-powered digital fraud & trust platform answering "Can I trust this digital interaction?"
Analyzes URLs, Emails, SMS/messages, QR codes → risk score 0-100, classification, threat
category, detected signals, explanation, recommended action.

## Scope (Part 1 — DONE, 2026-08)
Backend only. Node/Express + PostgreSQL (extended existing `nexnetra` repo). NO auth (deferred).
- Rule-based, explainable detection engine (backend/src/services/trustshield/).
- Scan APIs: POST /api/scan/{url,email,message,qr}; GET /api/scans, /api/scans/:id;
  DELETE /api/scans/:id; GET /api/dashboard. All no-auth, return 201/400/404.
- PostgreSQL persistence: scans + scan_signals (migration 002), parameterized SQL, FK+indexes.
- URL analyzer (offline, no SSRF), email/message scam detectors, QR decode (jimp+jsQR).
- Transparent scoring (0-29 SAFE / 30-69 SUSPICIOUS / 70-100 HIGH_RISK), explanation built
  only from detected signals. Dashboard aggregates from real DB data.
- 15 vitest unit tests passing; all endpoints verified via curl end-to-end.

## Out of scope / deferred
- Authentication (JWT/login) — existing code left untouched, not required by scan flow.
- ML service, frontend UI, live URL fetching/reputation — Agent 2.

## Backlog (Agent 2)
- P0: React scan UI + dashboard consuming the stable contract (see TRUSTSHIELD_PART1.md).
- P1: ML detection service; live URL reputation with SSRF-safe fetching.
- P2: re-enable auth + per-user scan history.

## Part 2 — Frontend + ML (DONE, 2026-08)
- React (Vite) UI, no auth: Landing, Dashboard, URL/Email/Message/QR scanners, reusable
  RiskResult (score ring + signals + explanation + recommendation), Scan History + detail, About.
- Python FastAPI ML service (ml-service/): LogisticRegression baseline (baseline-1). Real eval —
  accuracy 0.941, precision 0.930, recall 0.948, F1 0.939. POST /predict, /health, /metrics.
- Node->ML integration: mlClient posts URL features to ML service; adds ML_MODEL_RISK signal
  (fails open if ML down). Browser never calls ML directly.
- Services under supervisor: ts-backend (8001), ts-ml (5001), frontend (Vite 3000); PostgreSQL.
- Verified: testing_agent iteration_1 — backend 100% (18 pytest), frontend 100%, no issues.
  Backend unit tests 15/15 (vitest).

## Part 2 backlog (future)
- P1: ML text-classifier for message/email content (currently rule-based).
- P2: re-enable authentication + per-user history; live SSRF-safe URL reputation.

## ClickShield Threat Sandbox (DONE, 2026-08)
- New module: async URL sandbox with process-isolated Playwright worker (reduced-isolation preview).
- Full SSRF engine (IPv4/IPv6, private/loopback/link-local/reserved/multicast, cloud metadata,
  alternate encodings, DNS-rebinding via all-record + final-URL revalidation). Unit-tested.
- Deterministic evidence-based risk engine; verdicts incl Inconclusive/Analysis failed; confidence
  = evidence completeness. Output sanitized; URLs redacted; retention cleanup.
- APIs: POST/GET/GET report/GET screenshot/DELETE /api/sandbox/jobs. Rate-limited. States machine.
- Frontend /sandbox page (JS) with consent notice, progress, evidence cards, technical details,
  limitations. Nav + route added. Existing features preserved.
- Real Playwright verified against local fixtures (credential-form + cross-domain + screenshot).
- Tests: 43 vitest pass (incl SSRF categories, normalize, sanitize, risk engine, worker, cleanup).
- Eval (synthetic scoring, NOT live): precision 1.0, recall 0.57, F1 0.73 (3 conservative FNs).
- Deliverables: sandbox-deploy/{Dockerfile.worker,docker-compose.yml,k8s-worker.yaml}, CLICKSHIELD_SANDBOX.md.
- Public browsing DISABLED by default (SANDBOX_ALLOW_PUBLIC=false) until hardened worker deployed.
