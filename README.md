# PS 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

An enterprise-grade, lightweight cyber threat detection system designed for unidirectional and bidirectional IP network traffic analysis, calibrated detection, relational storage in PostgreSQL, and REST API distribution via FastAPI.

---

## Current Architecture & Status

- **Passive Live Packet Capture**: `scapy` / Npcap (Read-only, passive sniffer).
- **Bidirectional Flow Construction**: Temporal 5-tuple flow aggregation with active/idle timeouts.
- **Model Compatibility & Provenance**:
  - **DDoS Detector**: `PARTIALLY_COMPATIBLE` (Evaluated on forward/backward statistical distributions).
  - **Botnet C2 Detector**: `FULLY_COMPATIBLE` (Feature-semantics level; runtime live accuracy is *not* ground-truth validated).
  - **PortScan Detector**: `PARTIALLY_COMPATIBLE` (Single-flow anomaly detector; structural multi-flow limitation).
- **Threat Alert Engine**: Calibrated multi-threat triage with evidence generation and confidence bands.
- **Traffic Context**: All live Wi-Fi captured records are tagged with `traffic_context = "UNLABELED_LIVE"`. Detections represent *model suspicion*, not confirmed cyber attacks.
- **Backend & Storage (Step 17)**:
  - **Database**: PostgreSQL with SQLAlchemy ORM (3 normalized tables: `flows`, `alerts`, `model_status`).
  - **REST API**: FastAPI with Pydantic response models, CORS, pagination, filtering, and Swagger UI.
  - **Payload Safety**: **ZERO** payload storage. No decrypted TLS/QUIC, packet bytes, or payload fields.
  - **Network Safety**: Strictly **read-only**. The API never probes, blocks, scans, modifies, or transmits network packets.

---

## 1. Environment Configuration

Copy the example configuration file:

```bash
cp .env.example .env
```

Configure your PostgreSQL database connection in `.env`:

```env
DATABASE_URL=postgresql://postgres:root@localhost:5432/cyber_threats
CORS_ORIGINS=http://localhost:5173,http://127.0.0.1:5173
```

---

## 2. PostgreSQL Setup & Database Initialization

Ensure PostgreSQL is running locally (e.g., on default port `5432`). Create the database and initialize tables and indexes:

```bash
python scripts/init_database.py
```

Expected output:
```text
========================================
DATABASE INITIALIZATION
========================================
Connection:
SUCCESS

Tables:
flows
alerts
model_status

Indexes:
CREATED

========================================
```

---

## 3. Data Seeding

Seed existing live network flows (`data/processed/live/live_flows.jsonl`), generated alerts (`data/processed/live/alerts/threat_alerts.jsonl`), and model compatibility statuses:

```bash
python -m src.database.seed
```

This operation is idempotent: running it multiple times will not duplicate records.

---

## 4. Running the FastAPI Backend

Start the Uvicorn ASGI server:

```bash
python -m uvicorn src.api.main:app --reload --host 127.0.0.1 --port 8000
```

---

## 5. API Endpoints

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

---

## 6. Running Tests

Run database integration and schema tests:
```bash
python src/database/test_database.py
```

Run FastAPI endpoint and route tests:
```bash
python src/api/test_api.py
```
