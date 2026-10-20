# PS 26145 Cyber Threat Detector — Backend & Authentication

The backend engine provides passive network packet capture, unidirectional flow aggregation, multi-threat AI detection pipelines, PostgreSQL relational persistence, and secure REST API services with real session-based authentication and Role-Based Access Control (RBAC).

---

## Architecture Overview

- **`src/auth/`**: Authentication & authorization core:
  - Argon2id password hashing with timing attack mitigation (dummy verify on nonexistent accounts).
  - JWT token generation with unique JTI identifiers.
  - Server-side session tracking and revocation verification.
  - FastAPI dependency injection (`get_current_user`, `require_admin`).
- **`src/capture/`**: Scapy-based passive sniffer (zero packet payloads stored) and 5-tuple unidirectional flow aggregation.
- **`src/detection/`**: ML inference engines for DDoS (Random Forest), Botnet C2 (PCA/DBSCAN/Beaconing), and PortScan (Isolation Forest), unified through a stateful feature adapter.
- **`src/alerts/`**: Multi-threat fusion engine, confidence calibration, evidence generation, and rate suppression.
- **`src/database/`**: SQLAlchemy models and repositories for normalized relational storage (`flows`, `alerts`, `model_status`, `users`, `user_sessions`).
- **`src/api/`**: FastAPI REST API endpoints protected with session-based authentication, query filtering, CORS middleware, and OpenAPI documentation.
- **`scripts/`**: Operational utilities for administrator bootstrapping (`create_admin.py`), live API authentication verification (`verify_live_api_auth.py`), database initialization, and seeding.

---

## Authentication & Authorization Model

### 1. Password Security
- **Algorithm**: Argon2id via `argon2-cffi` (`time_cost=3`, `memory_cost=65536`, `parallelism=4`, salt length=16 bytes).
- **Password Policy**: Minimum 10 characters, at least 1 uppercase letter, 1 lowercase letter, 1 numeric digit, and 1 special symbol (`!@#$%^&*()_+-=[]{}|;:,.<>?`).
- **Timing Attack Mitigation**: When login fails due to a nonexistent email, a dummy Argon2 verification runs against a static benchmark hash so response times remain indistinguishable from existing accounts.

### 2. Session Strategy for React SPA
- **Session Transport**: `netra_session` cookie configured as:
  - `HttpOnly=True`: Inaccessible to client JavaScript, mitigating Cross-Site Scripting (XSS) credential theft.
  - `SameSite=Lax`: Mitigates Cross-Site Request Forgery (CSRF).
  - `Secure`: Configurable via `SESSION_COOKIE_SECURE` (`False` for local HTTP development, `True` for production HTTPS).
- **No Token in LocalStorage**: Sensitive JWT tokens or credentials are never stored in `localStorage` or `sessionStorage`.
- **Database-Backed Session Revocation**: Every session is registered in the `user_sessions` PostgreSQL table with a unique `token_jti`. Calling `POST /api/auth/logout` sets `is_revoked = True` in the database, invalidating the session immediately across all devices even if the token has not expired.
- **Brute Force Lockout**: Accounts are automatically locked for 15 minutes after 5 consecutive failed login attempts.

### 3. Role-Based Access Control (RBAC)
- **`admin`**: Full operational access. Authorized to view all telemetry, configure passive monitoring, and invoke `/api/capture/start` and `/api/capture/stop`.
- **`analyst`**: Read-only operator access. Authorized to inspect dashboard telemetry, network flows, threat alerts, and model statuses. Capture controls are strictly disabled and blocked with `403 Forbidden`.

---

## Setup & Running

### 1. Environment Configuration

Copy the example environment configuration:
```powershell
Copy-Item .env.example .env
```

Key environment variables:
| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `postgresql://postgres:password@localhost:5432/cyber_threats` | PostgreSQL connection string |
| `API_HOST` | `127.0.0.1` | Backend host bind address |
| `API_PORT` | `8000` | Backend port |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173` | Allowed frontend origins |
| `JWT_SECRET_KEY` | *(Set in .env)* | Secret key for signing session tokens |
| `JWT_ALGORITHM` | `HS256` | JWT signing algorithm |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `480` (8 hours) | Session token expiration duration |
| `SESSION_COOKIE_SECURE` | `False` (local) / `True` (prod) | Enforce Secure flag on cookies |
| `SESSION_COOKIE_SAMESITE` | `lax` | SameSite cookie attribute |

### 2. Database Initialization

Ensure PostgreSQL is running and initialize the database schema (creates `users`, `user_sessions`, `flows`, `alerts`, `model_status`):
```powershell
python scripts/init_database.py
```

### 3. Administrator Account Creation (No Public Registration)

Public sign-up is strictly disabled. The initial administrator account is provisioned via the secure host CLI tool:

**Interactive mode (with hidden password prompt):**
```powershell
python scripts/create_admin.py
```
Prompts:
```text
Enter administrator email: admin@soc.gov.in
Enter administrator full name [SOC Lead Administrator]: SOC Lead Administrator
Enter password (min 10 chars, uppercase, lowercase, number, symbol): [hidden]
Confirm password: [hidden]
```

**Non-interactive / automation mode:**
```powershell
python scripts/create_admin.py --email admin@soc.gov.in --name "SOC Lead Administrator" --password "CyberDefense2026!"
```

To update or reset an existing administrator account, provide `--force`:
```powershell
python scripts/create_admin.py --email admin@soc.gov.in --password "NewSecurePassword2026!" --force
```

### 4. Running the Applications

**Run Backend (FastAPI):**
```powershell
# From the backend/ folder:
..\venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000 --reload
```

**Run Frontend (Vite + React):**
```powershell
# From the frontend/ folder:
npm run dev
```
Open `http://localhost:5173` in your browser.

---

## Authentication Endpoints

| Method | Endpoint | Access | Description |
|---|---|---|---|
| `POST` | `/api/auth/login` | Public | Authenticates credentials, checks lockout, and sets `netra_session` HttpOnly cookie |
| `POST` | `/api/auth/logout` | Authenticated | Revokes session token in database and deletes `netra_session` cookie |
| `GET` | `/api/auth/me` | Authenticated | Returns profile of currently authenticated operator (`email`, `role`, `full_name`) |
| `GET` | `/health` | Public | System health check (`{"status": "ok", "service": "PS26145 API"}`) |

### Protected Telemetry Endpoints
All data endpoints require an authenticated session (`netra_session` cookie or `Authorization: Bearer <token>`):
- `GET /api/dashboard/overview`
- `GET /api/flows` & `GET /api/flows/{flow_id}`
- `GET /api/alerts` & `GET /api/alerts/{alert_id}`
- `GET /api/models/status`
- `GET /api/capture/status` & `GET /api/capture/interfaces`
- `POST /api/capture/start` *(Requires `admin` role)*
- `POST /api/capture/stop` *(Requires `admin` role)*

---

## Verification & Testing

### 1. Run Backend Unit & Integration Tests (100% Passed)
```powershell
python -m unittest discover -s src -p "test_*.py"
```
Includes 12 dedicated authentication & authorization tests (`src/api/test_auth.py`):
- Login success with valid credentials.
- Login rejection with invalid password (generic message).
- Login rejection with nonexistent account (timing attack defense).
- Unauthenticated rejection across all protected data endpoints (401).
- Token expiration verification (401).
- Session verification via `netra_session` cookie.
- Logout revocation check (subsequent requests rejected with 401).
- Role-based authorization for capture control (Analyst gets 403, Admin gets 200).
- Password hash verification (passwords never stored in plaintext).

### 2. Run Real HTTP Authentication Verification Against Live Server
```powershell
python scripts/verify_live_api_auth.py
```
Executes real HTTP requests against `http://127.0.0.1:8000` covering all 16 end-to-end security scenarios.

### 3. Build Frontend Production Bundle
```powershell
cd ../frontend
npm run build
```

---

## Local Development vs. Production Settings

| Setting | Local Development | Production Environment |
|---|---|---|
| Protocol | `http://` (`127.0.0.1` / `localhost`) | `https://` (TLS 1.3 enforced) |
| `SESSION_COOKIE_SECURE` | `False` (allows cookie over HTTP) | `True` (browser rejects cookie over plaintext HTTP) |
| `SESSION_COOKIE_SAMESITE` | `lax` | `lax` or `strict` |
| `CORS_ORIGINS` | `http://localhost:5173,http://127.0.0.1:5173` | Fully qualified domain (e.g. `https://netra.soc.gov.in`) |
| `JWT_SECRET_KEY` | Development passphrase | High-entropy random 256-bit key stored in secret vault |

---

## Remaining Security Considerations

1. **TLS / HTTPS**: In production, the API and frontend must be served behind a reverse proxy (e.g., NGINX, Caddy, or Cloudflare) with valid TLS certificates, and `SESSION_COOKIE_SECURE=True` must be enabled.
2. **Distributed Rate Limiting**: In multi-instance or high-throughput deployments, a distributed store such as Redis should be used for rate limiting and IP-based connection throttling.
3. **Hardware-Enforced Diode**: NETRA is designed for passive unidirectional traffic monitoring. Physical transmit lines (TX pins) should remain disconnected on sensor hardware to guarantee zero reverse packet transmission.
