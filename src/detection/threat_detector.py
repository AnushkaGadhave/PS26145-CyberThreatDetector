import json
import time
import logging
from pathlib import Path
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Tuple
import joblib
import numpy as np
import pandas as pd

from src.capture.flow_schema import FlowRecord
from src.detection.feature_adapter import FeatureAdapter

logger = logging.getLogger(__name__)


# CustomPCA definition matching the Step 8 C2 model artifact
class CustomPCA:
    def __init__(self, n_components=None, random_state=None):
        self.n_components = n_components
        self.random_state = random_state
        self.components_ = None
        self.explained_variance_ = None
        self.explained_variance_ratio_ = None
        self.mean_ = None
        self.n_components_ = None

    def transform(self, X):
        X = np.asarray(X, dtype=np.float64)
        X_centered = X - self.mean_
        return np.dot(X_centered, self.components_.T)

    def inverse_transform(self, X):
        X = np.asarray(X, dtype=np.float64)
        return np.dot(X, self.components_) + self.mean_

# Register CustomPCA in __main__ and sys.modules so joblib can deserialize it
import sys
setattr(sys.modules['__main__'], 'CustomPCA', CustomPCA)



@dataclass
class ThreatAlert:
    """Represents a structured multi-threat detection verdict for a network flow."""
    flow_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    duration: float
    total_packets: int
    total_bytes: int

    # Individual Model Predictions & Scores
    ddos_prediction: int
    ddos_probability: float

    c2_prediction: int
    c2_probability: float

    portscan_prediction: int
    portscan_anomaly_score: float

    # Multi-Threat Fusion Verdict
    detected_threats: List[str]
    threat_level: str  # 'BENIGN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to a serializable dictionary."""
        d = asdict(self)
        d['ddos_probability'] = round(d['ddos_probability'], 4)
        d['c2_probability'] = round(d['c2_probability'], 4)
        d['portscan_anomaly_score'] = round(d['portscan_anomaly_score'], 6)
        d['duration'] = round(d['duration'], 4)
        return d

    def to_json(self) -> str:
        """Convert alert to JSON string."""
        return json.dumps(self.to_dict())


class ThreatDetector:
    """
    Unified multi-threat detection engine.
    Ingests live FlowRecords and evaluates them across DDoS, C2, and PortScan models.
    """
    def __init__(
        self,
        ddos_model_path: str = "models/ddos/random_forest.pkl",
        ddos_config_path: str = "models/ddos/ddos_model_config.json",
        c2_models_dir: str = "models/c2",
        portscan_model_path: str = "models/portscan/isolation_forest.pkl",
        portscan_config_path: str = "models/portscan/portscan_model_config.json",
        alerts_jsonl_path: Optional[str] = "data/processed/live/threat_alerts.jsonl"
    ):
        self.alerts_jsonl_path = Path(alerts_jsonl_path) if alerts_jsonl_path else None
        if self.alerts_jsonl_path:
            self.alerts_jsonl_path.parent.mkdir(parents=True, exist_ok=True)

        # 1. Initialize Feature Adapter
        self.adapter = FeatureAdapter(
            ddos_config_path=ddos_config_path,
            c2_config_path=f"{c2_models_dir}/c2_model_config.json",
            portscan_config_path=portscan_config_path
        )

        # 2. Load DDoS Model
        self.ddos_model = None
        p_ddos = Path(ddos_model_path)
        if p_ddos.exists():
            try:
                self.ddos_model = joblib.load(p_ddos)
                logger.info(f"Loaded DDoS Random Forest model from {p_ddos}")
            except Exception as e:
                logger.error(f"Failed to load DDoS model {p_ddos}: {e}")

        # 3. Load PortScan Isolation Forest Model
        self.portscan_model = None
        self.portscan_threshold = 0.026465  # Default 5% normal baseline FPR
        p_ps = Path(portscan_model_path)
        if p_ps.exists():
            try:
                self.portscan_model = joblib.load(p_ps)
                # Read calibrated threshold from config if available
                p_cfg = Path(portscan_config_path)
                if p_cfg.exists():
                    with open(p_cfg, 'r') as f:
                        cfg = json.load(f)
                        self.portscan_threshold = cfg.get('calibrated_anomaly_thresholds', {}).get('5pct_normal_fpr_threshold_default', 0.026465)
                logger.info(f"Loaded PortScan Isolation Forest model from {p_ps} (Threshold: {self.portscan_threshold:.6f})")
            except Exception as e:
                logger.error(f"Failed to load PortScan model {p_ps}: {e}")

        # 4. Load C2 Model Components
        self.c2_scaler = None
        self.c2_pca = None
        self.c2_threshold = 0.78908
        p_c2 = Path(c2_models_dir)
        if p_c2.exists():
            try:
                scaler_p = p_c2 / "scaler.pkl"
                pca_p = p_c2 / "pca_transformer.pkl"
                thresh_p = p_c2 / "calibration_thresholds.json"
                if scaler_p.exists():
                    self.c2_scaler = joblib.load(scaler_p)
                if pca_p.exists():
                    self.c2_pca = joblib.load(pca_p)
                if thresh_p.exists():
                    with open(thresh_p, 'r') as f:
                        c2_thresh = json.load(f)
                        self.c2_threshold = c2_thresh.get('hybrid_threshold_5pct', 0.78908)
                logger.info(f"Loaded C2 PCA/Scaler models from {p_c2} (Threshold: {self.c2_threshold:.4f})")
            except Exception as e:
                logger.error(f"Failed to load C2 model components: {e}")

        self._evaluated_count = 0
        self._alerts_count = 0

    def evaluate_flow(self, flow: FlowRecord) -> ThreatAlert:
        """
        Evaluates a single FlowRecord across DDoS, C2, and PortScan detection pipelines.
        Returns a unified ThreatAlert verdict.
        """
        self._evaluated_count += 1
        detected_threats = []

        # --- A. DDoS Evaluation (Random Forest) ---
        ddos_pred = 0
        ddos_prob = 0.0
        if self.ddos_model is not None and self.adapter.ddos_features:
            try:
                df_ddos = self.adapter.to_ddos_dataframe(flow)
                probs = self.ddos_model.predict_proba(df_ddos)[0]
                ddos_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
                ddos_pred = 1 if ddos_prob >= 0.5 else 0
                if ddos_pred == 1:
                    detected_threats.append("DDoS")
            except Exception as e:
                logger.error(f"Error evaluating DDoS: {e}")

        # --- B. PortScan Evaluation (Isolation Forest) ---
        ps_pred = 0
        ps_score = 0.0
        if self.portscan_model is not None and self.adapter.portscan_features:
            try:
                df_ps = self.adapter.to_portscan_dataframe(flow)
                # Negate decision_function so higher score = stronger anomaly
                raw_df = self.portscan_model.decision_function(df_ps)[0]
                ps_score = float(-raw_df)
                ps_pred = 1 if ps_score >= self.portscan_threshold else 0
                if ps_pred == 1:
                    detected_threats.append("PortScan")
            except Exception as e:
                logger.error(f"Error evaluating PortScan: {e}")

        # --- C. Botnet C2 Evaluation (PCA / Beaconing Anomaly) ---
        c2_pred = 0
        c2_prob = 0.0
        if self.c2_scaler is not None and self.adapter.c2_features:
            try:
                df_c2 = self.adapter.to_c2_dataframe(flow)
                # Compute C2 heuristic beaconing and PCA reconstruction distance
                c2_scaled = self.c2_scaler.transform(df_c2)
                if self.c2_pca is not None:
                    c2_pca_proj = self.c2_pca.transform(c2_scaled)
                    # PCA reconstruction error as anomaly indicator
                    reconstructed = self.c2_pca.inverse_transform(c2_pca_proj)
                    rec_err = float(np.mean((c2_scaled - reconstructed) ** 2))
                    c2_prob = min(1.0, max(0.0, rec_err / (self.c2_threshold * 2.0)))
                else:
                    c2_prob = 0.0

                c2_pred = 1 if c2_prob >= 0.5 else 0
                if c2_pred == 1:
                    detected_threats.append("Botnet C2")
            except Exception as e:
                logger.error(f"Error evaluating C2: {e}")

        # --- D. Multi-Threat Triage & Threat Level Assignment ---
        if not detected_threats:
            threat_level = "BENIGN"
        elif len(detected_threats) >= 2 or ddos_prob >= 0.9:
            threat_level = "CRITICAL"
        elif ddos_pred == 1 or c2_pred == 1:
            threat_level = "HIGH"
        elif ps_pred == 1:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        alert = ThreatAlert(
            flow_id=flow.flow_id,
            timestamp=flow.start_time,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            duration=flow.duration,
            total_packets=flow.total_packets,
            total_bytes=flow.total_bytes,
            ddos_prediction=ddos_pred,
            ddos_probability=ddos_prob,
            c2_prediction=c2_pred,
            c2_probability=c2_prob,
            portscan_prediction=ps_pred,
            portscan_anomaly_score=ps_score,
            detected_threats=detected_threats if detected_threats else ["Normal/BENIGN"],
            threat_level=threat_level
        )

        if threat_level != "BENIGN":
            self._alerts_count += 1

        # Stream to alerts JSONL
        if self.alerts_jsonl_path:
            try:
                with open(self.alerts_jsonl_path, 'a', encoding='utf-8') as f:
                    f.write(alert.to_json() + '\n')
            except Exception as e:
                logger.error(f"Error logging alert: {e}")

        return alert
