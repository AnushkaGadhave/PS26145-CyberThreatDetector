import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
import pickle
import numpy as np
import pandas as pd
from scipy.spatial import cKDTree
from sklearn.preprocessing import StandardScaler

from src.capture.flow_schema import FlowRecord
from src.detection.threat_detector import CustomPCA, ThreatDetector

# 1. Load C2 Model Artifacts
models_dir = Path("models/c2")
with open(models_dir / "scaler.pkl", "rb") as f:
    scaler = pickle.load(f)
with open(models_dir / "pca_transformer.pkl", "rb") as f:
    pca = pickle.load(f)
core_samples = np.load(models_dir / "dbscan_core_samples.npy")
with open(models_dir / "calibration_thresholds.json", "r") as f:
    calib_thresholds = json.load(f)
with open(models_dir / "c2_model_config.json", "r") as f:
    model_config = json.load(f)

print("=== C2 MODEL ARTIFACTS LOADED ===")
print(f"Scaler features count: {len(scaler.mean_)}")
print(f"PCA components: {pca.n_components_} (components shape: {pca.components_.shape})")
print(f"DBSCAN core samples: {core_samples.shape}")
print(f"Calibration thresholds: {calib_thresholds}")

# 2. Build cKDTree on core samples
core_tree = cKDTree(core_samples)

# Load live flows
flows = []
with open("data/processed/live/live_flows.jsonl", "r") as f:
    for line in f:
        if line.strip():
            flows.append(json.loads(line))

detector = ThreatDetector(alerts_jsonl_path=None)

# Trace specific flows
# 1. Benign-looking flow: flow_tcp_e7a2c62f5731cd37 (Flow 4)
# 2. C2 flagged flow: flow_udp_d6b50081f846f309 (Flow 1)
# 3. Highest-confidence C2 flow: flow_tcp_29ca563253401ed3 (Flow 3)

target_flow_ids = [
    ("BENIGN_LOOKING", "flow_tcp_e7a2c62f5731cd37"),
    ("C2_FLAGGED_BROADCAST", "flow_udp_d6b50081f846f309"),
    ("HIGHEST_C2_FLOW", "flow_tcp_29ca563253401ed3")
]

target_dict = {tid: label for label, tid in target_flow_ids}

print("\n" + "="*80)
print("C2 DEEP AUDIT: TRACING INTERMEDIATE VALUES")
print("="*80)

# We will run all flows sequentially to maintain history
for i, flow_dict in enumerate(flows):
    rec = FlowRecord.from_dict(flow_dict)
    
    # 1. Feature extraction
    df_c2 = detector.adapter.to_c2_dataframe(rec)
    raw_feats = df_c2.iloc[0].to_dict()
    
    # 2. Scaler
    scaled_feats = scaler.transform(df_c2)
    
    # 3. PCA Projection & Reconstruction
    pca_proj = pca.transform(scaled_feats)
    reconstructed = pca.inverse_transform(pca_proj)
    rec_err = float(np.mean((scaled_feats - reconstructed) ** 2))
    
    # 4. DBSCAN nearest core sample distance
    dbscan_dist, _ = core_tree.query(pca_proj, k=1)
    dbscan_dist = float(dbscan_dist[0])
    dbscan_anom = 1 if dbscan_dist > calib_thresholds['dbscan_eps'] else 0
    
    # 5. Beaconing score
    # Note: in step 8 training, beaconing score was percentile rank of 6 features
    b_feats = calib_thresholds['beaconing_features']
    # Inspect raw values of beaconing features
    b_vals = {bf: raw_feats.get(bf, 0.0) for bf in b_feats}
    
    # 6. Current runtime C2 score (threat_detector.py)
    runtime_c2_score = min(1.0, max(0.0, rec_err / (detector.c2_threshold * 2.0)))
    runtime_pred = 1 if runtime_c2_score >= 0.50 else 0
    
    if rec.flow_id in target_dict:
        label = target_dict[rec.flow_id]
        print(f"\n>>> TARGET FLOW: [{label}] (ID: {rec.flow_id})")
        print(f"    Protocol: {rec.protocol}, {rec.src_ip}:{rec.src_port} -> {rec.dst_ip}:{rec.dst_port}")
        print(f"    Duration: {rec.duration:.4f}s, Packets: {rec.total_packets}, Bytes: {rec.total_bytes}")
        print(f"    --- Step 1: Raw C2 Features (Sample) ---")
        print(f"        IAT_Regularity_Causal:      {raw_feats['IAT_Regularity_Causal']:.4f}")
        print(f"        RepeatRatio_SrcDst_Causal:  {raw_feats['RepeatRatio_SrcDst_Causal']:.4f}")
        print(f"        DstFanoutRatio_Causal:      {raw_feats['DstFanoutRatio_Causal']:.4f}")
        print(f"        Src_Flows_60s:              {raw_feats['Src_Flows_60s']}")
        print(f"        Src_Flows_300s:             {raw_feats['Src_Flows_300s']}")
        print(f"        Src_Flows_BeforeOrAtT:      {raw_feats['Src_Flows_BeforeOrAtT']}")
        print(f"        SrcDst_Flows_BeforeOrAtT:   {raw_feats['SrcDst_Flows_BeforeOrAtT']}")
        print(f"        PacketsPerSecond:           {raw_feats['PacketsPerSecond']:.2f}")
        print(f"        BytesPerSecond:             {raw_feats['BytesPerSecond']:.2f}")
        print(f"    --- Step 2: StandardScaler Output ---")
        print(f"        Scaled vector norm:         {np.linalg.norm(scaled_feats):.4f}")
        print(f"        Scaled min / max:           {scaled_feats.min():.4f} / {scaled_feats.max():.4f}")
        print(f"    --- Step 3: PCA Projection ---")
        print(f"        PCA components vector (15): {np.round(pca_proj[0, :5], 4)} ...")
        print(f"        PCA Reconstruction MSE:     {rec_err:.6f}")
        print(f"    --- Step 4: DBSCAN Core Distance ---")
        print(f"        Nearest Core Distance:      {dbscan_dist:.4f} (Eps threshold: {calib_thresholds['dbscan_eps']:.4f})")
        print(f"        DBSCAN Outlier Flag:        {dbscan_anom}")
        print(f"    --- Step 5: Runtime Scoring & Verdict ---")
        print(f"        Runtime C2 Anomaly Score:   {runtime_c2_score:.4f}")
        print(f"        Calibrated C2 Threshold:    {detector.c2_threshold:.4f}")
        print(f"        Final Runtime Prediction:   {runtime_pred} ({'THREAT' if runtime_pred==1 else 'BENIGN'})")
