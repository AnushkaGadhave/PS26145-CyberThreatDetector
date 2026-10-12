import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pandas as pd
import numpy as np

from src.capture.flow_schema import FlowRecord
from src.detection.threat_detector import ThreatDetector
from src.alerts.alert_engine import AlertEngine

# Load live flows
flows = []
with open("data/processed/live/live_flows.jsonl", "r") as f:
    for line in f:
        if line.strip():
            flows.append(json.loads(line))

# Load Step 16 alerts
alerts = []
with open("data/processed/live/alerts/threat_alerts.jsonl", "r") as f:
    for line in f:
        if line.strip():
            alerts.append(json.loads(line))

alerts_by_flow = {a["flow_id"]: a for a in alerts}

detector = ThreatDetector(alerts_jsonl_path=None)

records = []
for flow_dict in flows:
    rec = FlowRecord.from_dict(flow_dict)
    alert = alerts_by_flow.get(rec.flow_id)
    
    # Run through feature adapter
    df_c2 = detector.adapter.to_c2_dataframe(rec)
    df_ps = detector.adapter.to_portscan_dataframe(rec)
    
    # PS Score
    raw_df = detector.portscan_model.decision_function(df_ps)[0]
    ps_score = float(-raw_df)
    
    # C2 Score
    c2_scaled = detector.c2_scaler.transform(df_c2)
    c2_pca_proj = detector.c2_pca.transform(c2_scaled)
    reconstructed = detector.c2_pca.inverse_transform(c2_pca_proj)
    rec_err = float(np.mean((c2_scaled - reconstructed) ** 2))
    c2_score = min(1.0, max(0.0, rec_err / (detector.c2_threshold * 2.0)))
    
    # Extract primary evidence feature & threshold from alert if present
    primary_ev_feat = "None"
    primary_ev_val = "None"
    primary_ev_th = "None"
    
    if alert and alert.get("evidence"):
        ev0 = alert["evidence"][0]
        primary_ev_feat = str(ev0.get("feature", "None"))
        primary_ev_val = str(ev0.get("value", "None"))
        primary_ev_th = str(ev0.get("threshold", "None"))
    
    # Formulate possible reason based on deep diagnostic audit
    fid = rec.flow_id
    if alert is None:
        possible_reason = "Alert suppressed by 30s stateful deduplication cache (recent alert already emitted for this source/destination pair)."
    elif alert["threat_class"] == "BENIGN":
        possible_reason = "Normal baseline flow characteristics; PCA reconstruction error and Isolation Forest anomaly score remained below decision thresholds."
    elif alert["threat_class"] == "BOTNET_C2":
        if rec.dst_ip == "255.255.255.255":
            possible_reason = "Cold-start warm-up artifact on LAN broadcast: first flow for host defaulted IAT_Regularity_Causal to 1.0 and RepeatRatio to 1.0, triggering beaconing heuristic on ordinary UDP broadcast."
        elif rec.total_packets <= 6:
            possible_reason = "Cold-start warm-up artifact: isolated short TCP/UDP flow with zero prior causal history defaulted IAT regularity to 1.0 and host flow count threshold."
        elif rec.dst_port == 53:
            possible_reason = "Host flow frequency escalation: recursive DNS queries during active browsing session accumulated Src_Flows_60s count to >= 10, triggering high C2 anomaly score."
        elif rec.dst_port == 5222:
            possible_reason = "Interactive messaging protocol traffic (Jabber/WhatsApp) with regular packet intervals flagged by uncalibrated timing heuristic under cold-start conditions."
        else:
            possible_reason = "Web browsing telemetry/API connection evaluated under uncalibrated causal history; elevated Src_Flows_60s counter combined with default regularity."
    elif alert["threat_class"] == "MULTI_THREAT":
        if rec.total_bytes > 100000:
            possible_reason = "Cascading alert escalation: high-volume bulk TLS/HTTPS transfer (out of distribution for CTU-13/CIC-IDS2017 baselines) triggered high PCA reconstruction error and Isolation Forest anomaly score; triage logic compounded weak anomalies into CRITICAL MULTI_THREAT."
        else:
            possible_reason = "Cascading alert escalation: interactive HTTPS connection with small TCP handshake packets triggered both PortScan IF sensitivity and C2 frequency heuristic, compounded into CRITICAL MULTI_THREAT without confidence weighting."
    else:
        possible_reason = "Model anomaly score exceeded baseline threshold on out-of-distribution live Wi-Fi traffic."

    threat_cls = alert["threat_class"] if alert else "SUPPRESSED_DUPLICATE"
    det_name = alert["detector"] if alert else "SuppressionFilter"
    pred_val = 1 if (alert and alert["threat_class"] != "BENIGN") else 0
    score_val = alert.get("confidence") if alert else None
    conf_val = alert.get("confidence") if alert else None
    sev_val = alert["severity"] if alert else "SUPPRESSED"
    mod_stat = alert["model_status"] if alert else "FULLY_COMPATIBLE"

    records.append({
        "flow_id": rec.flow_id,
        "src_ip": rec.src_ip,
        "dst_ip": rec.dst_ip,
        "src_port": rec.src_port or 0,
        "dst_port": rec.dst_port or 0,
        "protocol": rec.protocol,
        "threat_class": threat_cls,
        "detector": det_name,
        "prediction": pred_val,
        "score": round(score_val, 4) if score_val is not None else round(max(c2_score, ps_score), 4),
        "confidence": round(conf_val, 4) if conf_val is not None else None,
        "severity": sev_val,
        "model_status": mod_stat,
        "evidence_feature": primary_ev_feat,
        "evidence_value": primary_ev_val,
        "evidence_threshold": primary_ev_th,
        "duration": round(rec.duration, 4),
        "total_packets": rec.total_packets,
        "total_bytes": rec.total_bytes,
        "packets_per_second": round(rec.packets_per_second, 2),
        "bytes_per_second": round(rec.bytes_per_second, 2),
        "c2_score": round(c2_score, 4),
        "c2_threshold": round(detector.c2_threshold, 4),
        "portscan_score": round(ps_score, 4),
        "portscan_threshold": round(detector.portscan_threshold, 4),
        "possible_reason": possible_reason
    })

df_fp = pd.DataFrame(records)
out_csv = Path("evaluation/live_false_positive_analysis.csv")
out_csv.parent.mkdir(parents=True, exist_ok=True)
df_fp.to_csv(out_csv, index=False)
print(f"Saved {len(df_fp)} rows to {out_csv}")
print(df_fp[['flow_id', 'threat_class', 'severity', 'c2_score', 'portscan_score', 'possible_reason']].to_string())
