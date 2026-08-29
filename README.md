# TrustShield

**AI-powered digital fraud detection & digital trust platform.** Answers one question:
*"Can I trust this digital interaction?"* — for URLs, emails, SMS/messages and QR codes.

Every scan returns a **0–100 risk score**, a **classification** (SAFE / SUSPICIOUS / HIGH_RISK),
a **threat category**, the **detected signals** (evidence), a plain-language **explanation**, and a
**recommended action**. Detection is explainable and rule-based, augmented by a machine-learning
phishing-likelihood model. *Authentication is intentionally out of scope for this MVP.*

## Architecture
```
React (Vite)  →  Node.js + Express  →  Detection Engine  →  ML Service (FastAPI)
                                    →  Risk Engine        →  PostgreSQL
```
The browser talks **only** to the Node/Express API. Node calls the Python ML service internally.

```
frontend/     React UI (scanners, dashboard, history, result)
backend/      Express API + detection/risk engine + PostgreSQL (Part 1)
ml-service/   FastAPI + scikit-learn baseline model
```

## Setup

### 1. PostgreSQL
```bash
service postgresql start
createdb nexnetra   # or: CREATE DATABASE nexnetra;
```

### 2. Backend (Node/Express)  — port 8001
```bash
cp .env.example .env          # set DATABASE_URL, JWT_SECRET, ML_SERVICE_URL, PORT=8001
npm install
npm run migrate               # applies migrations (creates scans + scan_signals)
node backend/src/server.js     # health: GET /api/health
```

### 3. ML service (FastAPI)  — port 5001
```bash
cd ml-service
pip install -r requirements.txt
python train.py               # trains model.pkl + metrics.json
uvicorn app:app --host 0.0.0.0 --port 5001
```

### 4. Frontend (Vite/React)  — port 3000
```bash
cd frontend
cp .env.example .env          # VITE_API_URL empty = same-origin /api
npm run start                 # or: npm run dev
```

## Environment variables
| Scope | Var | Purpose |
|---|---|---|
| backend / root `.env` | `DATABASE_URL` | PostgreSQL connection |
| | `JWT_SECRET` | required by server bootstrap (auth deferred) |
| | `PORT` | backend port (8001) |
| | `ML_SERVICE_URL` | ML service base URL (default http://127.0.0.1:5001) |
| frontend `.env` | `VITE_API_URL` | API base; empty = same-origin `/api` |

## API overview (all `/api`, no auth)
| Method | Path | Body |
|---|---|---|
| POST | `/api/scan/url` | `{ "url" }` |
| POST | `/api/scan/email` | `{ "sender"?, "subject"?, "content" }` |
| POST | `/api/scan/message` | `{ "content" }` |
| POST | `/api/scan/qr` | multipart `image` (≤2MB) or `{ "content" }` |
| GET | `/api/scans` · `/api/scans/:id` · DELETE `/api/scans/:id` | scan history |
| GET | `/api/dashboard` | real aggregated stats |

Result contract: `{ riskScore, classification, threatCategory, signals[], explanation, recommendedAction, ml? }`.
Thresholds: `0–29 SAFE`, `30–69 SUSPICIOUS`, `70–100 HIGH_RISK`.

## ML service
`POST /predict` → `{ "probability", "modelVersion": "baseline-1" }` from a Logistic Regression model
trained on URL structural features. `GET /metrics` returns the evaluation.

**Evaluation (test set, 1000 samples):** accuracy **0.941**, precision **0.930**, recall **0.948**,
F1 **0.939**; false positives 34, false negatives 25. The model *supports* the rule engine (adds an
`ML_MODEL_RISK` signal for high-likelihood URLs) — it never overrides it.

## Demo (hackathon)
Message Scanner → "Bank / OTP scam" example:
> *"URGENT: Your account will be suspended today. Verify immediately and share the OTP … http://icici-verify.paypa1.com/login"*

Demonstrates urgency detection, account/OTP manipulation, URL extraction, suspicious URL + brand
impersonation, ML likelihood, risk score, explanation, and recommended action — the full attack
chain (Message → Fake Website → Credential Theft → OTP Theft → Financial Fraud).

## Known limitations
- Rule-based + baseline ML only (no deep learning); ML applies to URL features.
- URL analysis is fully offline (no live reputation/DNS/SSL fetch) — avoids SSRF.
- Authentication deferred: scanners/dashboard are public in the MVP.
- QR decoding supports standard QR images up to 2MB.
