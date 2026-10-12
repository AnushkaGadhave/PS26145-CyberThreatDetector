"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.alerts.alert_pipeline

End-to-end processing pipeline connecting live flows to detectors, alert engine, and alert writers.
"""

import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any, Callable
import numpy as np

from src.capture.flow_schema import FlowRecord
from src.detection.threat_detector import ThreatDetector
from src.alerts.alert_schema import ThreatAlert, DetectorResult
from src.alerts.alert_engine import AlertEngine
from src.alerts.alert_writer import AlertWriter
from src.alerts.evidence_builder import EvidenceBuilder

logger = logging.getLogger(__name__)


class AlertPipeline:
    """
    End-to-end alert pipeline orchestrator.
    Ingests FlowRecords, executes multi-threat detectors, builds evidence, applies severity policies,
    and streams alerts to persistent logs.
    """
    def __init__(
        self,
        mode: str = "ALERT",  # 'ALERT' (suspicious only) or 'AUDIT' (all flows)
        traffic_context: str = "UNLABELED_LIVE",  # 'LAB_ATTACK', 'LAB_BENIGN', 'REPLAY', 'UNLABELED_LIVE', 'PRODUCTION_MONITORING'
        policy_path: str = "config/alert_policy.json",
        suppression_seconds: float = 30.0,
        jsonl_path: str = "data/processed/live/alerts/threat_alerts.jsonl",
        csv_path: str = "data/processed/live/alerts/threat_alerts.csv",
        alert_callback: Optional[Callable[[ThreatAlert], None]] = None
    ):
        self.traffic_context = traffic_context
        self.detector = ThreatDetector(alerts_jsonl_path=None)
        self.engine = AlertEngine(
            policy_config_path=policy_path,
            suppression_window_seconds=suppression_seconds,
            mode=mode
        )
        self.writer = AlertWriter(jsonl_path=jsonl_path, csv_path=csv_path)
        self.alert_callback = alert_callback

    def process_flow(self, flow: FlowRecord) -> Optional[ThreatAlert]:
        """
        Process a single FlowRecord through the complete detection and alerting pipeline.
        """
        detector_results: List[DetectorResult] = []

        # 1. DDoS Detection
        if self.detector.ddos_model is not None:
            df_ddos = self.detector.adapter.to_ddos_dataframe(flow)
            probs = self.detector.ddos_model.predict_proba(df_ddos)[0]
            ddos_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            ddos_pred = 1 if ddos_prob >= 0.5 else 0
            
            ddos_ev, ddos_sum = EvidenceBuilder.build_ddos_evidence(
                flow=flow,
                probability=ddos_prob,
                model_status="PARTIALLY_COMPATIBLE"
            )
            conf_band = "HIGH_CONFIDENCE" if ddos_prob >= 0.85 else ("MEDIUM_CONFIDENCE" if ddos_prob >= 0.50 else "LOW_CONFIDENCE")
            detector_results.append(DetectorResult(
                detector="RandomForest_DDoS",
                threat_class="DDoS",
                prediction=ddos_pred,
                score=ddos_prob,
                confidence=ddos_prob,
                confidence_band=conf_band,
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                evidence=ddos_ev,
                reason=ddos_sum
            ))

        # 2. PortScan Detection
        if self.detector.portscan_model is not None:
            df_ps = self.detector.adapter.to_portscan_dataframe(flow)
            raw_df = self.detector.portscan_model.decision_function(df_ps)[0]
            ps_score = float(-raw_df)
            ps_pred = 1 if ps_score >= self.detector.portscan_threshold else 0
            
            ps_ev, ps_sum = EvidenceBuilder.build_portscan_evidence(
                flow=flow,
                anomaly_score=ps_score,
                threshold=self.detector.portscan_threshold,
                model_status="PARTIALLY_COMPATIBLE"
            )
            detector_results.append(DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=ps_pred,
                score=ps_score,
                confidence=None,  # Continuous anomaly score, not a probability
                confidence_band="LOW_CONFIDENCE",
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                evidence=ps_ev,
                reason=ps_sum
            ))

        # 3. Botnet C2 Detection (with Causal Warm-up History Validation)
        if self.detector.c2_scaler is not None:
            df_c2 = self.detector.adapter.to_c2_dataframe(flow)
            c2_feat_dict = df_c2.iloc[0].to_dict()
            tot_src_flows = c2_feat_dict.get('Src_Flows_BeforeOrAtT', 0)
            tot_src_dst_flows = c2_feat_dict.get('SrcDst_Flows_BeforeOrAtT', 0)

            c2_scaled = self.detector.c2_scaler.transform(df_c2)
            if self.detector.c2_pca is not None:
                c2_pca_proj = self.detector.c2_pca.transform(c2_scaled)
                reconstructed = self.detector.c2_pca.inverse_transform(c2_pca_proj)
                rec_err = float(np.mean((c2_scaled - reconstructed) ** 2))
                c2_score = min(1.0, max(0.0, rec_err / (self.detector.c2_threshold * 2.0)))
            else:
                c2_score = 0.0

            # Warm-up condition: C2 timing evaluation requires historical observation state
            if tot_src_flows < 3 or tot_src_dst_flows < 2:
                c2_status = "INSUFFICIENT_HISTORY"
                c2_pred = 0
                c2_ev, c2_sum = EvidenceBuilder.build_c2_evidence(
                    flow=flow,
                    c2_features_dict=c2_feat_dict,
                    score=c2_score,
                    model_status="INSUFFICIENT_HISTORY"
                )
                detector_results.append(DetectorResult(
                    detector="HybridPCA_Botnet_C2",
                    threat_class="BOTNET_C2",
                    prediction=0,
                    score=c2_score,
                    confidence=None,
                    confidence_band="NOT_APPLICABLE",
                    compatible="INSUFFICIENT_HISTORY",
                    status="INSUFFICIENT_HISTORY",
                    evidence=c2_ev,
                    reason="Not enough repeated source-destination observations."
                ))
            else:
                c2_pred = 1 if c2_score >= 0.50 else 0
                c2_ev, c2_sum = EvidenceBuilder.build_c2_evidence(
                    flow=flow,
                    c2_features_dict=c2_feat_dict,
                    score=c2_score,
                    model_status="FULLY_COMPATIBLE"
                )
                conf_band = "HIGH_CONFIDENCE" if c2_score >= 0.85 else ("MEDIUM_CONFIDENCE" if c2_score >= 0.50 else "LOW_CONFIDENCE")
                detector_results.append(DetectorResult(
                    detector="HybridPCA_Botnet_C2",
                    threat_class="BOTNET_C2",
                    prediction=c2_pred,
                    score=c2_score,
                    confidence=c2_score,
                    confidence_band=conf_band,
                    compatible="FULLY_COMPATIBLE",
                    status="READY",
                    evidence=c2_ev,
                    reason=c2_sum
                ))

        # 4. Alert Engine Evaluation & Policy Application
        alert = self.engine.evaluate_detector_results(flow, detector_results, traffic_context=self.traffic_context)

        # 5. Persistence
        if alert is not None:
            self.writer.write_alert(alert)
            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as e:
                    logger.error(f"Error in alert callback: {e}")

        return alert
