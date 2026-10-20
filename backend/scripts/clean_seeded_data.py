"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Script: scripts/clean_seeded_data.py

Identifies and cleanly removes pre-seeded demo records from PostgreSQL.
Uses exact flow_id and alert_id matching against live_flows.jsonl and threat_alerts.jsonl
so that only seeded demo rows are deleted, preserving any real future observations.
"""

import sys
import json
from pathlib import Path

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.database.database import SessionLocal
from src.database.models import FlowModel, AlertModel


def clean_seeded_records():
    print("========================================")
    print("CLEANING SEEDED DEMO RECORDS")
    print("========================================")

    flows_file = project_root / "data/processed/live/live_flows.jsonl"
    alerts_file = project_root / "data/processed/live/alerts/threat_alerts.jsonl"

    seed_fids = set()
    if flows_file.exists():
        with open(flows_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    seed_fids.add(json.loads(line)["flow_id"])

    seed_aids = set()
    if alerts_file.exists():
        with open(alerts_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    seed_aids.add(json.loads(line)["alert_id"])

    print(f"Identified {len(seed_fids)} seeded flow IDs from {flows_file.name}")
    print(f"Identified {len(seed_aids)} seeded alert IDs from {alerts_file.name}")

    db = SessionLocal()
    try:
        # Delete only records matching the exact seeded IDs
        deleted_alerts = 0
        if seed_aids:
            deleted_alerts = db.query(AlertModel).filter(AlertModel.alert_id.in_(seed_aids)).delete(synchronize_session=False)

        deleted_flows = 0
        if seed_fids:
            deleted_flows = db.query(FlowModel).filter(FlowModel.flow_id.in_(seed_fids)).delete(synchronize_session=False)

        db.commit()

        remaining_flows = db.query(FlowModel).count()
        remaining_alerts = db.query(AlertModel).count()

        print("----------------------------------------")
        print(f"Deleted Seeded Alerts: {deleted_alerts}")
        print(f"Deleted Seeded Flows:  {deleted_flows}")
        print(f"Remaining DB Flows:    {remaining_flows}")
        print(f"Remaining DB Alerts:   {remaining_alerts}")
        print("========================================")
        print("DATABASE READY FOR REAL RUNTIME OBSERVATIONS")
        print("========================================")
    except Exception as e:
        db.rollback()
        print(f"Error during cleanup: {e}")
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    clean_seeded_records()
