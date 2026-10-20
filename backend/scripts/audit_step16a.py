import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pandas as pd
import numpy as np
import joblib

from src.capture.flow_schema import FlowRecord
from src.detection.threat_detector import ThreatDetector
from src.alerts.alert_pipeline import AlertPipeline
from src.alerts.alert_engine import AlertEngine
from src.alerts.evidence_builder import EvidenceBuilder

# Load live flows
flows = []
with open("data/processed/live/live_flows.jsonl", "r") as f:
    for line in f:
        if line.strip():
            flows.append(json.loads(line))

print(f"Total live flows: {len(flows)}")

# Load existing Step 16 alerts
alerts = []
with open("data/processed/live/alerts/threat_alerts.jsonl", "r") as f:
    for line in f:
        if line.strip():
            alerts.append(json.loads(line))

print(f"Total Step 16 alerts: {len(alerts)}")

alerts_by_flow = {a["flow_id"]: a for a in alerts}

detector = ThreatDetector(alerts_jsonl_path=None)

# Let's inspect each flow through the adapter and detector
rows = []
for flow_dict in flows:
    rec = FlowRecord.from_dict(flow_dict)
    alert = alerts_by_flow.get(rec.flow_id)
    
    # Run through feature adapter
    df_c2 = detector.adapter.to_c2_dataframe(rec)
    df_ps = detector.adapter.to_portscan_dataframe(rec)
    df_ddos = detector.adapter.to_ddos_dataframe(rec)
    
    # DDoS
    ddos_prob = 0.0
    if detector.ddos_model is not None:
        probs = detector.ddos_model.predict_proba(df_ddos)[0]
        ddos_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
    
    # PS
    ps_score = 0.0
    if detector.portscan_model is not None:
        raw_df = detector.portscan_model.decision_function(df_ps)[0]
        ps_score = float(-raw_df)
    
    # C2
    c2_score = 0.0
    rec_err = 0.0
    if detector.c2_scaler is not None and detector.c2_pca is not None:
        c2_scaled = detector.c2_scaler.transform(df_c2)
        c2_pca_proj = detector.c2_pca.transform(c2_scaled)
        reconstructed = detector.c2_pca.inverse_transform(c2_pca_proj)
        rec_err = float(np.mean((c2_scaled - reconstructed) ** 2))
        c2_score = min(1.0, max(0.0, rec_err / (detector.c2_threshold * 2.0)))
    
    # Features of interest
    iat_reg = df_c2.iloc[0].get("IAT_Regularity_Causal", 0.0)
    rep_ratio = df_c2.iloc[0].get("RepeatRatio_SrcDst_Causal", 0.0)
    fanout = df_c2.iloc[0].get("DstFanoutRatio_Causal", 0.0)
    src_60s = df_c2.iloc[0].get("Src_Flows_60s", 0.0)
    
    print(f"Flow {rec.flow_id} ({rec.protocol} {rec.src_ip}:{rec.src_port} -> {rec.dst_ip}:{rec.dst_port}):")
    print(f"  Alert ThreatClass: {alert['threat_class'] if alert else 'NONE'}, Sev: {alert['severity'] if alert else 'NONE'}")
    print(f"  DDoS Prob: {ddos_prob:.4f}, PS Score: {ps_score:.4f} (th={detector.portscan_threshold:.4f}), C2 Score: {c2_score:.4f} (rec_err={rec_err:.4f}, th={detector.c2_threshold:.4f})")
    print(f"  C2 Feats: IAT_Reg={iat_reg:.2f}, RepRatio={rep_ratio:.2f}, Fanout={fanout:.2f}, Src60s={src_60s}")
    print()
