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
