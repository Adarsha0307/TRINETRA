# Test Credentials

TrustShield MVP has **no authentication** (intentionally deferred). The scanners, dashboard
and scan history are publicly accessible — no login, users, or credentials required.

Services (preview/local):
- Frontend (React/Vite): port 3000
- Backend (Node/Express): port 8001, base path `/api`
- ML service (FastAPI): port 5001 (internal, called only by backend)
- PostgreSQL: database `nexnetra`
