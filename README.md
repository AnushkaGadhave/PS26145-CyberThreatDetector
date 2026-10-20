# PS 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

An enterprise-grade, lightweight cyber threat detection system designed for unidirectional and bidirectional IP network traffic analysis, calibrated detection, relational storage in PostgreSQL, and REST API distribution via FastAPI with an interactive React + TypeScript frontend dashboard.

---

## Repository Structure

The repository is organized into distinct, modular application directories:

```text
PS26145-CyberThreatDetector/
├── frontend/                 # React 19 + TypeScript + Vite web dashboard
│   ├── src/                  # Components, telemetry models, and UI views
│   ├── public/               # Public assets and icons
│   ├── package.json          # Node dependencies and build scripts
│   └── vite.config.ts        # Vite build configuration
├── backend/                  # Python 3.13 + FastAPI + ML detection engine
│   ├── src/
│   │   ├── api/              # FastAPI REST endpoints and route handlers
│   │   ├── alerts/           # Alert engine, calibration, evidence builder
│   │   ├── capture/          # Scapy sniffer & 5-tuple bidirectional flow builder
│   │   ├── database/         # SQLAlchemy models, repositories, and seed logic
│   │   └── detection/        # ML models (DDoS, C2, PortScan) & feature adapter
│   ├── config/               # Alert policy thresholds & attack label mappings
│   ├── data/                 # Datasets and captures (raw, processed, live)
│   ├── models/               # Model weights, configs, scalers, and DBSCAN samples
│   ├── notebooks/            # Jupyter research, training, and analysis notebooks
│   ├── evaluation/           # ROC curves, confusion matrices, audit reports
│   ├── scripts/              # Database initialization, seeding, and verification
│   ├── requirements.txt      # Python dependencies
│   └── .env.example          # Backend environment configuration template
├── docs/
│   └── reference/            # Visual reference media and screen recordings
├── .gitignore                # Root Git ignore rules
└── README.md                 # Root project documentation
```

---

## Core Architecture & Status

- **Passive Live Packet Capture**: `scapy` / Npcap (Read-only, passive sniffer).
- **Bidirectional Flow Construction**: Temporal 5-tuple flow aggregation with active/idle timeouts.
- **Model Compatibility & Provenance**:
  - **DDoS Detector**: `PARTIALLY_COMPATIBLE` (Evaluated on forward/backward statistical distributions).
  - **Botnet C2 Detector**: `FULLY_COMPATIBLE` (Feature-semantics level; runtime live accuracy is *not* ground-truth validated).
  - **PortScan Detector**: `PARTIALLY_COMPATIBLE` (Single-flow anomaly detector; structural multi-flow limitation).
- **Threat Alert Engine**: Calibrated multi-threat triage with evidence generation and confidence bands.
- **Traffic Context**: All live Wi-Fi captured records are tagged with `traffic_context = "UNLABELED_LIVE"`. Detections represent *model suspicion*, not confirmed cyber attacks.
- **Backend & Storage**:
  - **Database**: PostgreSQL with SQLAlchemy ORM (3 normalized tables: `flows`, `alerts`, `model_status`).
  - **REST API**: FastAPI with Pydantic response models, CORS, pagination, filtering, and Swagger UI.
  - **Payload Safety**: **ZERO** payload storage. No decrypted TLS/QUIC, packet bytes, or payload fields.
  - **Network Safety**: Strictly **read-only**. The system never probes, blocks, scans, modifies, or transmits network packets.

---

## Quickstart: Running Backend & Frontend Independently

### 1. Running the Backend (FastAPI & ML Engine)

Open PowerShell and navigate into the `backend/` directory:

```powershell
cd backend
```

#### Step A: Configure Environment
Copy the example configuration:
```powershell
Copy-Item .env.example .env
```
Ensure your PostgreSQL `DATABASE_URL` is set in `.env` (default: `postgresql://postgres:root@localhost:5432/cyber_threats`).

#### Step B: Initialize Database Schema
Ensure PostgreSQL is running, then initialize tables and indexes:
```powershell
python scripts/init_database.py
```

#### Step C: Seed Initial Telemetry & Model Statuses
Seed existing live flows, calibrated alerts, and model operational disclosures:
```powershell
python -m src.database.seed
```

#### Step D: Start FastAPI ASGI Server
```powershell
python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```
- Interactive API Docs (Swagger UI): [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- OpenAPI Specification: [http://127.0.0.1:8000/openapi.json](http://127.0.0.1:8000/openapi.json)

#### Step E: Run Backend Tests & Live Verification
```powershell
# Run all unit and integration tests
python -m unittest discover -s src -p "test_*.py"

# Verify all 10 live API endpoints against PostgreSQL
python scripts/verify_api_live.py
```

---

### 2. Running the Frontend (React + Vite Dashboard)

Open a separate PowerShell terminal and navigate into the `frontend/` directory:

```powershell
cd frontend
```

#### Step A: Install Dependencies
```powershell
npm install
```

#### Step B: Start Vite Development Server
```powershell
npm run dev
```
The frontend interface will be available at [http://localhost:5173](http://localhost:5173).

#### Step C: Build for Production
```powershell
npm run build
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status check |
| `GET` | `/api/flows` | Paginated flow records with filters (`protocol`, `src_ip`, `dst_ip`, `traffic_context`) |
| `GET` | `/api/flows/{flow_id}` | Detailed single flow record (HTTP 404 if not found) |
| `GET` | `/api/alerts` | Paginated alerts with filters (`severity`, `threat_class`, `detector`, `traffic_context`, `start_time`, `end_time`) |
| `GET` | `/api/alerts/{alert_id}` | Detailed alert record with evidence, evidence summary, and recommended action |
| `GET` | `/api/alerts/recent` | Latest 20 alerts ordered chronologically descending (for polling) |
| `GET` | `/api/alerts/summary` | Aggregate alert summary, severity counts, threat class counts, and unlabeled alert stats |
| `GET` | `/api/models/status` | Model compatibility statuses and operational limitation notes |
| `GET` | `/api/dashboard/overview` | Compact JSON overview for security dashboard visualizations |
| `GET` | `/docs` | Interactive Swagger API documentation |
| `GET` | `/openapi.json` | OpenAPI 3.0 specification |
