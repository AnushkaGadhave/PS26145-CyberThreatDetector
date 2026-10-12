"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.database.seed

Idempotent seeding script for importing existing live flow records, calibrated alerts,
and model operational statuses into PostgreSQL.
Uses flow_id and alert_id as deduplication keys.
"""

import os
import sys
import json
import logging
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
env_path = project_root / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
else:
    load_dotenv()

from src.database.database import SessionLocal, init_db
from src.database.repository import FlowRepository, AlertRepository, ModelStatusRepository

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


def seed_model_status(db):
    """Seed the 3 core model statuses with scientific compatibility disclosures."""
    models_data = [
        {
            "model_name": "DDoS",
            "status": "PARTIALLY_COMPATIBLE",
            "compatible": "PARTIALLY_COMPATIBLE",
            "reason": "Trained on CIC-IDS2017 Friday DDoS (Random Forest); subflow volumetric and flag features approximated during lightweight streaming extraction. Prototype only; not production validated."
        },
        {
            "model_name": "BOTNET_C2",
            "status": "FULLY_COMPATIBLE",
            "compatible": "FULLY_COMPATIBLE",
            "reason": "Trained on CTU-13 Scenario 42 (PCA/DBSCAN/Beaconing); feature semantics fully compatible with causal rolling history. Runtime accuracy on unlabeled live Wi-Fi requires domain adaptation and is not ground-truth validated."
        },
        {
            "model_name": "RECON_PORTSCAN",
            "status": "PARTIALLY_COMPATIBLE",
            "compatible": "PARTIALLY_COMPATIBLE",
            "reason": "Trained on CIC-IDS2017 Tuesday normal baseline (Isolation Forest); single-flow statistical outlier indicator without host destination-port fan-out tracking. Prototype triage indicator only."
        }
    ]

    count = 0
    for m in models_data:
        ModelStatusRepository.create_or_update(
            db=db,
            model_name=m["model_name"],
            status=m["status"],
            compatible=m["compatible"],
            reason=m["reason"]
        )
        count += 1
    logger.info(f"Seeded/verified {count} model status records.")
    return count


def seed_flows(db, jsonl_path: Path):
    """Import flow records idempotently from live_flows.jsonl."""
    if not jsonl_path.exists():
        logger.warning(f"Flow file {jsonl_path} does not exist; skipping flow seeding.")
        return 0

    count = 0
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            data = json.loads(line_str)
            flow_data = {
                "flow_id": data["flow_id"],
                "timestamp": data.get("start_time", 0.0),
                "start_time": data.get("start_time", 0.0),
                "last_seen": data.get("last_seen", 0.0),
                "src_ip": data["src_ip"],
                "dst_ip": data["dst_ip"],
                "src_port": data.get("src_port"),
                "dst_port": data.get("dst_port"),
                "protocol": data["protocol"],
                "duration": data.get("duration", 0.0),
                "total_packets": data.get("total_packets", 0),
                "total_bytes": data.get("total_bytes", 0),
                "forward_packets": data.get("forward_packets", 0),
                "backward_packets": data.get("backward_packets", 0),
                "forward_bytes": data.get("forward_bytes", 0),
                "backward_bytes": data.get("backward_bytes", 0),
                "packets_per_second": data.get("packets_per_second", 0.0),
                "bytes_per_second": data.get("bytes_per_second", 0.0),
                "syn_count": data.get("syn_count", 0),
                "ack_count": data.get("ack_count", 0),
                "fin_count": data.get("fin_count", 0),
                "rst_count": data.get("rst_count", 0),
                "psh_count": data.get("psh_count", 0),
                "urg_count": data.get("urg_count", 0),
                "iat_mean": data.get("iat_mean", 0.0),
                "iat_std": data.get("iat_std", 0.0),
                "iat_min": data.get("iat_min", 0.0),
                "iat_max": data.get("iat_max", 0.0),
                "traffic_context": data.get("traffic_context", "UNLABELED_LIVE"),
            }
            FlowRepository.create_or_update(db, flow_data)
            count += 1

    logger.info(f"Seeded/verified {count} flow records from {jsonl_path.name}.")
    return count


def seed_alerts(db, jsonl_path: Path):
    """Import threat alerts idempotently from threat_alerts.jsonl."""
    if not jsonl_path.exists():
        logger.warning(f"Alert file {jsonl_path} does not exist; skipping alert seeding.")
        return 0

    count = 0
    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if not line_str:
                continue
            data = json.loads(line_str)
            alert_data = {
                "alert_id": data["alert_id"],
                "timestamp": data.get("timestamp", 0.0),
                "flow_id": data["flow_id"],
                "src_ip": data["src_ip"],
                "dst_ip": data["dst_ip"],
                "src_port": data.get("src_port"),
                "dst_port": data.get("dst_port"),
                "protocol": data["protocol"],
                "threat_class": data["threat_class"],
                "threat_category": data.get("threat_category", data["threat_class"]),
                "confidence": data.get("confidence"),
                "confidence_band": data.get("confidence_band", "LOW_CONFIDENCE"),
                "severity": data["severity"],
                "detector": data["detector"],
                "model_status": data.get("model_status", "FULLY_COMPATIBLE"),
                "evidence": data.get("evidence", []),
                "evidence_summary": data.get("evidence_summary", ""),
                "recommended_action": data.get("recommended_action", ""),
                "traffic_context": data.get("traffic_context", "UNLABELED_LIVE"),
            }
            AlertRepository.create_or_update(db, alert_data)
            count += 1

    logger.info(f"Seeded/verified {count} alert records from {jsonl_path.name}.")
    return count


def run_seed():
    """Execute complete database seeding process."""
    init_db()
    if SessionLocal is None:
        logger.error("SessionLocal is not available. Check database connection.")
        return False

    db = SessionLocal()
    try:
        flows_file = project_root / "data/processed/live/live_flows.jsonl"
        alerts_file = project_root / "data/processed/live/alerts/threat_alerts.jsonl"

        models_count = seed_model_status(db)
        flows_count = seed_flows(db, flows_file)
        alerts_count = seed_alerts(db, alerts_file)

        print("\n========================================")
        print("DATABASE SEEDING COMPLETE")
        print("========================================")
        print(f"Model Statuses: {models_count}")
        print(f"Flows Seeded:   {flows_count}")
        print(f"Alerts Seeded:  {alerts_count}")
        print("========================================\n")
        return True
    finally:
        db.close()


if __name__ == "__main__":
    run_seed()
