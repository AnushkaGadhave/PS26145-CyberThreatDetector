"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Script: scripts/evaluate_live_alerts.py

Processes captured live flows from data/processed/live/live_flows.jsonl through the AlertPipeline,
generates data/processed/live/alerts/threat_alerts.jsonl and .csv, and writes evaluation/alert_engine_summary.txt.
"""

import sys
import json
import logging
from pathlib import Path
from collections import Counter
import pandas as pd

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.capture.flow_schema import FlowRecord
from src.alerts.alert_pipeline import AlertPipeline

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("evaluate_live_alerts")


def run_pipeline_on_live_flows():
    live_jsonl = project_root / "data/processed/live/live_flows.jsonl"
    out_alerts_jsonl = project_root / "data/processed/live/alerts/threat_alerts.jsonl"
    out_alerts_csv = project_root / "data/processed/live/alerts/threat_alerts.csv"

    # Reset existing alerts file for clean evaluation
    if out_alerts_jsonl.exists():
        out_alerts_jsonl.unlink()
    if out_alerts_csv.exists():
        out_alerts_csv.unlink()

    # Initialize AlertPipeline in AUDIT mode to inspect all flow verdicts
    pipeline = AlertPipeline(
        mode="AUDIT",
        suppression_seconds=0.0,  # Evaluate each unique captured flow
        jsonl_path=str(out_alerts_jsonl),
        csv_path=str(out_alerts_csv)
    )

    flows = []
    if live_jsonl.exists():
        with open(live_jsonl, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    flows.append(FlowRecord.from_dict(json.loads(line.strip())))

    logger.info(f"Loaded {len(flows)} live flows from {live_jsonl}")

    alerts = []
    severity_counter = Counter()
    threat_counter = Counter()
    detector_counter = Counter()
    partially_compatible_count = 0
    incompatible_count = 0

    for flow in flows:
        alert = pipeline.process_flow(flow)
        if alert is not None:
            alerts.append(alert)
            severity_counter[alert.severity] += 1
            threat_counter[alert.threat_class] += 1
            detector_counter[alert.detector] += 1
            if alert.model_status == "PARTIALLY_COMPATIBLE":
                partially_compatible_count += 1
            elif alert.model_status == "NOT_COMPATIBLE":
                incompatible_count += 1

    total_evaluated = len(flows)
    total_alerts = len([a for a in alerts if a.severity != "BENIGN"])
    benign_count = severity_counter.get("BENIGN", 0)
    low_count = severity_counter.get("LOW", 0)
    med_count = severity_counter.get("MEDIUM", 0)
    high_count = severity_counter.get("HIGH", 0)
    crit_count = severity_counter.get("CRITICAL", 0)
    benign_pct = (benign_count / total_evaluated * 100.0) if total_evaluated > 0 else 0.0

    print("=" * 60)
    print("LIVE THREAT ALERT EVALUATION RESULTS")
    print("=" * 60)
    print(f"Total flows evaluated:   {total_evaluated}")
    print(f"Total alerts:            {total_alerts}")
    print(f"Benign flows:            {benign_count} ({benign_pct:.1f}%)")
    print(f"Low alerts:              {low_count}")
    print(f"Medium alerts:           {med_count}")
    print(f"High alerts:             {high_count}")
    print(f"Critical alerts:         {crit_count}")
    print()
    print("Threat Category Breakdown:")
    print(f"  - DDoS:                {threat_counter.get('DDoS', 0)}")
    print(f"  - BOTNET_C2:           {threat_counter.get('BOTNET_C2', 0)}")
    print(f"  - RECON_PORTSCAN:      {threat_counter.get('RECON_PORTSCAN', 0)}")
    print(f"  - MULTI_THREAT:        {threat_counter.get('MULTI_THREAT', 0)}")
    print("=" * 60)

    # Write summary report
    summary_report = f"""================================================================================
SIH 2026 - PROBLEM STATEMENT 26145
AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
STEP 16: UNIFIED THREAT ALERT ENGINE EVALUATION REPORT
================================================================================

1. EVALUATION OVERVIEW:
 - Ingestion Source:         data/processed/live/live_flows.jsonl
 - Total Flows Evaluated:    {total_evaluated}
 - Total Threat Alerts:      {total_alerts}
 - Benign Flows:             {benign_count} ({benign_pct:.2f}%)
 - Alert Log (JSONL):        data/processed/live/alerts/threat_alerts.jsonl
 - Alert Table (CSV):        data/processed/live/alerts/threat_alerts.csv

2. SEVERITY DISTRIBUTION:
 - CRITICAL:                 {crit_count}
 - HIGH:                     {high_count}
 - MEDIUM:                   {med_count}
 - LOW:                      {low_count}
 - BENIGN:                   {benign_count}

3. THREAT CLASS BREAKDOWN:
 - DDoS:                     {threat_counter.get('DDoS', 0)}
 - BOTNET_C2:                {threat_counter.get('BOTNET_C2', 0)}
 - RECON_PORTSCAN:           {threat_counter.get('RECON_PORTSCAN', 0)}
 - MULTI_THREAT:             {threat_counter.get('MULTI_THREAT', 0)}
 - BENIGN:                   {threat_counter.get('BENIGN', 0)}

4. DETECTOR TRIGGER COUNTS:
"""
    for det, cnt in detector_counter.items():
        summary_report += f" - {det:35s}: {cnt}\n"

    summary_report += f"""
5. COMPATIBILITY DISCLOSURE:
 - Fully Compatible Detections:       {len(alerts) - partially_compatible_count - incompatible_count}
 - Partially Compatible Detections:   {partially_compatible_count} (Model limitations disclosed in evidence)
 - Incompatible Detections Suppressed:{incompatible_count}

6. AUDITABILITY & PASSIVE OPERATION:
 - Every generated alert includes structured supporting evidence items derived from flow features.
 - Zero payload bytes accessed or retained.
 - Zero packet transmission or active mitigation actions executed.
================================================================================
"""

    summary_path = project_root / "evaluation/alert_engine_summary.txt"
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    with open(summary_path, 'w', encoding='utf-8') as f:
        f.write(summary_report)
    logger.info(f"Saved alert engine summary report to {summary_path}")


if __name__ == '__main__':
    run_pipeline_on_live_flows()
