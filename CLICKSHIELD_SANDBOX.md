# ClickShield Threat Sandbox — Module Documentation

Safely inspects suspicious URLs and returns **explainable** security evidence. Built into the
existing TrustShield/ClickShield repo (Node/Express + PostgreSQL + React/Vite). No authentication
(MVP). **All existing functionality is preserved.**

> ⚠️ **Development / reduced-isolation mode.** In this preview the worker runs as a separate Node
> **process** (never inside the API process). Process separation is **NOT** equivalent to container
> isolation. Live browsing of arbitrary public URLs is **disabled by default**; production must run
> the worker via the hardened container in `sandbox-deploy/`.

---

## 1. Repository audit (findings)
- **Stack:** Node.js + Express + PostgreSQL backend; React + Vite frontend (JS, some TS UI components).
- **Existing controls reused:** `helmet`, `cors`, `express-rate-limit`, `originCheck`, ordered SQL
  migrations (`backend/migrations`), central error handler, and a **pluggable Google Safe Browsing**
  check in `backend/src/services/urlScanner/threatIntel.js` (API-key-gated).
- **Reused for scoring:** the existing rule engine `services/trustshield/urlAnalyzer.js`
  (punycode / IP / lookalike / keyword detection).
- No container runtime is available in the preview → dynamic browsing is gated off by default.

## 2. Architecture
```
React (/sandbox)
   │  POST /api/sandbox/jobs        (202 + jobId, returns immediately)
   ▼
Express API  ──create──▶ PostgreSQL (sandbox_jobs, redacted URLs, JSONB report)
   │  in-memory bounded queue (SANDBOX_CONCURRENCY)
   ▼
jobManager  ──validating──▶ SSRF engine (DNS + IP classification, revalidated per hop)
            ──analyzing───▶ static analysis (rules + Safe Browsing)
            ──fork(child)─▶ DISPOSABLE worker process → Playwright/Chromium
                              (fresh context, downloads off, permissions denied,
                               timeouts, size caps) → defensive telemetry only → exits
   ▼
Risk engine (deterministic, evidence-based) → sanitized report → PostgreSQL
   ▲  GET /api/sandbox/jobs/:id, /report, /screenshot, DELETE
React polls status → renders escaped evidence
```
The API process **never** navigates the suspicious URL. The worker receives a **minimal env**
(no `DATABASE_URL`, `JWT_SECRET`, or API keys).

## 3. API contract
| Method | Path | Result |
|---|---|---|
| POST | `/api/sandbox/jobs` `{ "url" }` | `202` `{ id, status:"queued", pollUrl, reportUrl, isolationMode, notice }` |
| GET | `/api/sandbox/jobs` | recent jobs (summary) |
| GET | `/api/sandbox/jobs/:id` | `{ id, status, riskScore, riskLevel, confidence, error, expiresAt }` |
| GET | `/api/sandbox/jobs/:id/report` | full report (`409` if not ready, `410` if expired) |
| GET | `/api/sandbox/jobs/:id/screenshot` | temporary artifact (if present) |
| DELETE | `/api/sandbox/jobs/:id` | `204` (cancels + deletes + purges artifacts) |

**Job states:** `queued → validating → analyzing → completed | failed | expired`.
Validation errors and SSRF blocks return `400` at create time or set the job `failed` with a reason.

**Report shape:** `{ riskScore(0–100), riskLevel, confidence, confidenceBasis, findings[]
{code,title,source(observed|reputation|rule|heuristic),weight,evidence,whyItMatters,consequence,
recommendation,confidence,timestamp}, evidenceNotCollected[], dataSources[], limitations[], observed{…} }`.
Verdicts: **Low observed risk / Suspicious / High risk / Known malicious / Inconclusive / Analysis failed**
(never "completely safe").

## 4. Security controls
- **SSRF** (`services/sandbox/ssrf.js`): http/https only; blocks embedded credentials; blocks
  localhost/`.local`/`.internal`; IPv4 loopback/private/CGNAT/link-local/reserved/multicast;
  IPv6 loopback/ULA/link-local/multicast + IPv4-mapped; **cloud metadata** (169.254.169.254);
  **alternate encodings** (decimal/hex/octal); **DNS resolution checks every A/AAAA record**
  (rebinding defense) and is **revalidated on the final URL** inside the worker.
- **Worker hardening:** fresh browser context per job, `acceptDownloads:false`, permissions denied,
  service workers blocked, non-http(s)/blocked-host requests aborted, nav + job timeouts, screenshot
  size cap, disposable (process exits after each job).
- **Privacy:** only redacted URLs stored (token/PII params → `[REDACTED]`); logs use a host+path
  label only; screenshots/artifacts auto-deleted at retention (`SANDBOX_RETENTION_MINUTES`).
- **Output sanitization:** all target-supplied strings stripped of control chars, length-capped, and
  schemes neutralized; React renders everything as escaped text (no untrusted HTML).
- **Rate limiting:** per-IP limiter on job creation (`SANDBOX_CREATE_RATE_LIMIT`).

## 5. Threat model (summary)
- **Assets:** the API host, its DB/secrets, internal network. **Adversary:** a malicious target URL.
- **Mitigated:** SSRF to internal/metadata services; DNS rebinding (pre-nav + final-URL revalidation
  + request-time host block); credential/secret exposure to the worker (minimal env); persistent
  state carryover (fresh context, disposable); drive-by downloads (blocked); stored-XSS via report
  (sanitized + escaped); resource exhaustion (timeouts, concurrency, size caps, rate limit).
- **Residual (preview):** process isolation is not a kernel/container boundary; subresource SSRF is
  enforced by literal-host checks (not full per-subresource DNS); no per-job network namespace.
  These are closed by the production container/K8s configs.

## 6. Deployment (production isolation)
- `sandbox-deploy/Dockerfile.worker` — Playwright base, non-root `pwuser`.
- `sandbox-deploy/docker-compose.yml` — `read_only`, `cap_drop: ALL`, `no-new-privileges`, tmpfs,
  `pids_limit`, mem/cpu limits, egress-only network.
- `sandbox-deploy/k8s-worker.yaml` — `runAsNonRoot`, `readOnlyRootFilesystem`, `drop: ALL`,
  `allowPrivilegeEscalation:false`, `seccompProfile: RuntimeDefault`, resource limits, and a
  **NetworkPolicy** that excludes RFC1918 / link-local / metadata from egress.
- Set `SANDBOX_ALLOW_PUBLIC=true` **only** once the worker runs behind this isolation.

## 7. Reproduce tests & evaluation
```bash
# Unit + integration (SSRF, normalization, sanitization, risk engine, worker, cleanup)
cd backend && npx vitest run                       # 43 tests
# Risk-engine scoring evaluation on labeled synthetic evidence (NOT live accuracy)
node scripts/sandbox-eval.mjs                       # writes ../test_reports/sandbox-eval-results.json
```

## 8. Honest status
**Works in this preview:** async job API + states; SSRF engine (all categories unit-tested); URL
normalization/redaction; deterministic risk engine + sanitization; **real Playwright dynamic
analysis against local fixtures** (credential-form + cross-domain-action detection + screenshot);
retention cleanup; frontend page. Google Safe Browsing is pluggable and **off** (no key).

**Restricted/off by default:** live browsing of arbitrary public URLs (static+reputation only).

**Requires production deployment:** genuine container isolation (read-only rootfs, dropped caps,
no-new-privileges, per-job network policy) via `sandbox-deploy/`.

**Not claimed:** 100% detection, guaranteed safety, or production-grade isolation in preview.
The risk-engine evaluation measures scoring on synthetic evidence, not real-world detection accuracy.
