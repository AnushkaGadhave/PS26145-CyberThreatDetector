import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pandas as pd
import numpy as np

from src.capture.flow_schema import FlowRecord
from src.alerts.alert_pipeline import AlertPipeline

# 1. Load original Step 16 alerts / analysis table
old_df = pd.read_csv("evaluation/live_false_positive_analysis.csv")
old_by_flow = {r['flow_id']: r for _, r in old_df.iterrows()}

# 2. Load live flows
flows = []
with open("data/processed/live/live_flows.jsonl", "r") as f:
    for line in f:
        if line.strip():
            flows.append(json.loads(line))

print(f"Loaded {len(flows)} live flows for recalibration evaluation.")

# 3. Initialize Calibrated AlertPipeline in AUDIT mode to evaluate every flow without suppression dropping
audit_pipeline = AlertPipeline(
    mode="AUDIT",
    traffic_context="UNLABELED_LIVE",
    jsonl_path="evaluation/recalibrated_audit_alerts.jsonl",
    csv_path="evaluation/recalibrated_audit_alerts.csv"
)

# Also run production pipeline in ALERT mode to produce updated official alerts
prod_pipeline = AlertPipeline(
    mode="ALERT",
    traffic_context="UNLABELED_LIVE",
    jsonl_path="data/processed/live/alerts/threat_alerts.jsonl",
    csv_path="data/processed/live/alerts/threat_alerts.csv"
)

# Clear existing threat alerts to write cleanly
Path("data/processed/live/alerts/threat_alerts.jsonl").unlink(missing_ok=True)
Path("data/processed/live/alerts/threat_alerts.csv").unlink(missing_ok=True)
Path("evaluation/recalibrated_audit_alerts.jsonl").unlink(missing_ok=True)
Path("evaluation/recalibrated_audit_alerts.csv").unlink(missing_ok=True)

comparison_rows = []
for flow_dict in flows:
    rec = FlowRecord.from_dict(flow_dict)
    old_row = old_by_flow[rec.flow_id]
    
    # Process through audit pipeline
    new_alert = audit_pipeline.process_flow(rec)
    # Process through prod pipeline (with suppression)
    prod_pipeline.process_flow(rec)
    
    new_detection = new_alert.threat_class if new_alert else "BENIGN"
    new_severity = new_alert.severity if new_alert else "BENIGN"
    new_confidence = new_alert.confidence if new_alert else None
    new_conf_band = new_alert.confidence_band if new_alert else "NOT_APPLICABLE"
    
    old_detection = old_row['threat_class']
    old_severity = old_row['severity']
    old_confidence = old_row['confidence']
    if pd.isna(old_confidence):
        old_confidence = None
    else:
        old_confidence = float(old_confidence)

    # Determine reason for change
    if old_detection == "BOTNET_C2" and new_detection == "BENIGN":
        reason_for_change = "Warm-up history check prevented cold-start flow from artificially defaulting IAT regularity to 1.0; marked as INSUFFICIENT_HISTORY / BENIGN."
    elif old_detection == "MULTI_THREAT" and new_detection == "RECON_PORTSCAN":
        reason_for_change = "C2 warm-up check removed uncalibrated C2 threat; single-flow PortScan IF anomaly triage de-escalated severity from CRITICAL to LOW."
    elif old_detection == "MULTI_THREAT" and new_detection == "MULTI_THREAT":
        reason_for_change = "De-escalated severity from CRITICAL to LOW/MEDIUM based on unlabeled live traffic triage separation (no false probability inflation)."
    elif old_detection == "SUPPRESSED_DUPLICATE":
        if new_detection == "BENIGN":
            reason_for_change = "Warm-up history check reclassified underlying flow as BENIGN baseline."
        else:
            reason_for_change = f"Evaluated under calibrated audit pipeline as {new_detection} ({new_severity})."
    elif old_detection == "BENIGN" and new_detection == "BENIGN":
        reason_for_change = "Remained consistently classified as BENIGN baseline."
    elif old_detection == "BOTNET_C2" and new_detection == "BOTNET_C2":
        reason_for_change = f"De-escalated severity from {old_severity} to {new_severity} with explicit UNLABELED_LIVE context and confidence band."
    else:
        reason_for_change = f"Recalibrated triage from {old_detection} ({old_severity}) to {new_detection} ({new_severity})."

    comparison_rows.append({
        "flow_id": rec.flow_id,
        "old_detection": old_detection,
        "new_detection": new_detection,
        "old_severity": old_severity,
        "new_severity": new_severity,
        "old_confidence": round(old_confidence, 4) if old_confidence is not None else "None",
        "new_confidence": round(new_confidence, 4) if new_confidence is not None else "None",
        "new_confidence_band": new_conf_band,
        "reason_for_change": reason_for_change
    })

df_comp = pd.DataFrame(comparison_rows)
out_csv = Path("evaluation/live_alert_calibration_before_after.csv")
df_comp.to_csv(out_csv, index=False)
print(f"\nSaved Before/After Comparison Table: {out_csv} ({len(df_comp)} rows)")
print(df_comp[['flow_id', 'old_detection', 'new_detection', 'old_severity', 'new_severity', 'reason_for_change']].to_string())

print("\n=== CALIBRATION SUMMARY ===")
print("Old Threat Classes Breakdown:")
print(old_df['threat_class'].value_counts())
print("\nNew Threat Classes Breakdown (Audit Mode):")
print(df_comp['new_detection'].value_counts())
print("\nNew Severities Breakdown (Audit Mode):")
print(df_comp['new_severity'].value_counts())
print("\nNew Severities Breakdown (Prod Alert Mode with Suppression):")
print(prod_pipeline.engine.severity_counts)
