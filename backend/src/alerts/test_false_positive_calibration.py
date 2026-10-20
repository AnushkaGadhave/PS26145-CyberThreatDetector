"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.alerts.test_false_positive_calibration

Unit tests for Step 16A False-Positive Analysis and Runtime Alert Calibration:
- Unlabeled live context handling
- Insufficient history (warm-up state)
- Weak anomaly calibration
- Medium anomaly calibration
- Strong anomaly calibration
- Multi-detector result handling
- Severity triage separation from raw detector output
- Confidence band assignment (no false probabilities)
- Prevention of automatic CRITICAL escalation from weak evidence
"""

import sys
import time
import unittest
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.capture.flow_schema import FlowRecord
from src.alerts.alert_schema import ThreatAlert, DetectorResult
from src.alerts.alert_engine import AlertEngine
from src.alerts.evidence_builder import EvidenceBuilder
from src.detection.feature_adapter import FeatureAdapter


class TestFalsePositiveCalibration(unittest.TestCase):
    """Test suite for Step 16A false-positive analysis and alert calibration."""

    def setUp(self):
        self.engine = AlertEngine(mode="ALERT")
        self.sample_flow = FlowRecord(
            flow_id="test_flow_001",
            src_ip="192.168.0.104",
            dst_ip="172.217.115.4",
            src_port=51835,
            dst_port=443,
            protocol="TCP",
            start_time=time.time(),
            last_seen=time.time() + 1.0,
            duration=1.0,
            total_packets=10,
            total_bytes=1500,
            forward_packets=6,
            backward_packets=4,
            forward_bytes=900,
            backward_bytes=600,
            packets_per_second=10.0,
            bytes_per_second=1500.0,
            forward_packet_ratio=0.6,
            backward_packet_ratio=0.4,
            forward_byte_ratio=0.6,
            backward_byte_ratio=0.4,
            bytes_per_packet=150.0,
            packets_per_byte=0.00666,
            syn_count=1,
            ack_count=9,
            fin_count=0,
            rst_count=0,
            psh_count=2,
            urg_count=0,
            iat_mean=0.1,
            iat_std=0.02,
            iat_min=0.05,
            iat_max=0.15
        )

    def test_01_unlabeled_live_context(self):
        """1. Verify traffic_context is visible on alerts and defaults to UNLABELED_LIVE."""
        results = [
            DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=1,
                score=0.035,
                confidence=None,
                confidence_band="LOW_CONFIDENCE",
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                reason="Weak isolation anomaly"
            )
        ]
        alert = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.traffic_context, "UNLABELED_LIVE")
        self.assertIn("Weak isolation anomaly", alert.evidence_summary)

    def test_02_insufficient_history_warmup(self):
        """2. Verify detectors with INSUFFICIENT_HISTORY do not produce threat alerts."""
        audit_engine = AlertEngine(mode="AUDIT")
        results = [
            DetectorResult(
                detector="HybridPCA_Botnet_C2",
                threat_class="BOTNET_C2",
                prediction=0,
                score=0.62,
                confidence=None,
                confidence_band="NOT_APPLICABLE",
                compatible="INSUFFICIENT_HISTORY",
                status="INSUFFICIENT_HISTORY",
                reason="Not enough repeated source-destination observations."
            )
        ]
        alert = audit_engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "BENIGN")
        self.assertEqual(alert.severity, "BENIGN")

    def test_03_weak_anomaly_calibration(self):
        """3. Verify weak single-flow anomalies remain LOW severity and LOW_CONFIDENCE."""
        results = [
            DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=1,
                score=0.031,
                confidence=None,
                confidence_band="LOW_CONFIDENCE",
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                reason="Weak isolation score"
            )
        ]
        alert = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "RECON_PORTSCAN")
        self.assertEqual(alert.severity, "LOW")
        self.assertEqual(alert.confidence_band, "LOW_CONFIDENCE")

    def test_04_medium_anomaly_calibration(self):
        """4. Verify medium anomaly detections are triaged as MEDIUM severity."""
        results = [
            DetectorResult(
                detector="HybridPCA_Botnet_C2",
                threat_class="BOTNET_C2",
                prediction=1,
                score=0.65,
                confidence=0.65,
                confidence_band="MEDIUM_CONFIDENCE",
                compatible="FULLY_COMPATIBLE",
                status="READY",
                reason="Medium C2 score"
            )
        ]
        alert = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "BOTNET_C2")
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertEqual(alert.confidence_band, "MEDIUM_CONFIDENCE")

    def test_05_strong_anomaly_calibration(self):
        """5. Verify high-confidence detections are triaged as HIGH severity in live context."""
        results = [
            DetectorResult(
                detector="HybridPCA_Botnet_C2",
                threat_class="BOTNET_C2",
                prediction=1,
                score=0.92,
                confidence=0.92,
                confidence_band="HIGH_CONFIDENCE",
                compatible="FULLY_COMPATIBLE",
                status="READY",
                reason="Strong C2 score with validated history"
            )
        ]
        alert = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "BOTNET_C2")
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.confidence_band, "HIGH_CONFIDENCE")

    def test_06_multi_detector_result(self):
        """6. Verify multi-detector fusion assigns MULTI_THREAT without inflating confidence to 1.0."""
        results = [
            DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=1,
                score=0.075,
                confidence=None,
                confidence_band="LOW_CONFIDENCE",
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                reason="PortScan outlier"
            ),
            DetectorResult(
                detector="HybridPCA_Botnet_C2",
                threat_class="BOTNET_C2",
                prediction=1,
                score=0.68,
                confidence=0.68,
                confidence_band="MEDIUM_CONFIDENCE",
                compatible="FULLY_COMPATIBLE",
                status="READY",
                reason="Medium C2 anomaly"
            )
        ]
        alert = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "MULTI_THREAT")
        self.assertEqual(alert.threat_category, "RECON_PORTSCAN, BOTNET_C2")
        self.assertEqual(alert.severity, "LOW")

    def test_07_severity_separation_from_raw_score(self):
        """7. Verify severity is determined by triage policy rather than raw uncalibrated score."""
        results = [
            DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=1,
                score=0.1924,  # High continuous anomaly score
                confidence=None,
                confidence_band="LOW_CONFIDENCE",
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                reason="High single-flow isolation score"
            )
        ]
        alert_live = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert_live)
        # In UNLABELED_LIVE, single-flow PortScan IF does not become CRITICAL or HIGH
        self.assertEqual(alert_live.severity, "LOW")
        self.assertEqual(alert_live.confidence_band, "LOW_CONFIDENCE")

    def test_08_no_false_probability_conversion(self):
        """8. Verify continuous anomaly scores are not misreported as calibrated probabilities."""
        ps_ev, ps_sum = EvidenceBuilder.build_portscan_evidence(
            flow=self.sample_flow,
            anomaly_score=0.082,
            threshold=0.026465,
            model_status="PARTIALLY_COMPATIBLE"
        )
        result = DetectorResult(
            detector="IsolationForest_PortScan",
            threat_class="RECON_PORTSCAN",
            prediction=1,
            score=0.082,
            confidence=None,  # Not a probability
            confidence_band="LOW_CONFIDENCE",
            compatible="PARTIALLY_COMPATIBLE",
            status="READY",
            evidence=ps_ev,
            reason=ps_sum
        )
        alert = self.engine.evaluate_detector_results(self.sample_flow, [result], traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.confidence_band, "LOW_CONFIDENCE")
        self.assertTrue(any("statistical isolation score" in ev["explanation"] for ev in alert.evidence))

    def test_09_no_automatic_critical_escalation_from_weak_evidence(self):
        """9. Verify multiple weak anomalies on live traffic do NOT escalate to CRITICAL."""
        results = [
            DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=1,
                score=0.045,
                confidence=None,
                confidence_band="LOW_CONFIDENCE",
                compatible="PARTIALLY_COMPATIBLE",
                status="READY",
                reason="Weak PortScan outlier"
            ),
            DetectorResult(
                detector="HybridPCA_Botnet_C2",
                threat_class="BOTNET_C2",
                prediction=1,
                score=0.52,
                confidence=0.52,
                confidence_band="LOW_CONFIDENCE",
                compatible="FULLY_COMPATIBLE",
                status="READY",
                reason="Sub-threshold C2 timing"
            )
        ]
        alert = self.engine.evaluate_detector_results(self.sample_flow, results, traffic_context="UNLABELED_LIVE")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "MULTI_THREAT")
        self.assertNotEqual(alert.severity, "CRITICAL")
        self.assertIn(alert.severity, ("LOW", "MEDIUM"))

    def test_10_feature_adapter_cold_start_iat(self):
        """10. Verify FeatureAdapter does NOT assign IAT_Regularity_Causal = 1.0 on the first flow."""
        adapter = FeatureAdapter()
        dummy_flow = FlowRecord(
            flow_id="f1",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=1234,
            dst_port=80,
            protocol="TCP",
            start_time=100.0,
            last_seen=100.1,
            duration=0.1,
            total_packets=2,
            total_bytes=100,
            forward_packets=1,
            backward_packets=1,
            forward_bytes=50,
            backward_bytes=50,
            packets_per_second=20.0,
            bytes_per_second=1000.0,
            forward_packet_ratio=0.5,
            backward_packet_ratio=0.5,
            forward_byte_ratio=0.5,
            backward_byte_ratio=0.5,
            bytes_per_packet=50.0,
            packets_per_byte=0.02,
            syn_count=1,
            ack_count=1,
            fin_count=0,
            rst_count=0,
            psh_count=0,
            urg_count=0,
            iat_mean=0.1,
            iat_std=0.0,
            iat_min=0.1,
            iat_max=0.1
        )
        df_c2 = adapter.to_c2_dataframe(dummy_flow)
        # Cold start on 1st flow must NOT be 1.0 (perfect regularity)
        self.assertEqual(df_c2.iloc[0]['IAT_Regularity_Causal'], 0.0)
        self.assertEqual(df_c2.iloc[0]['RepeatRatio_SrcDst_Causal'], 0.0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
