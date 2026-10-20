"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.alerts.test_alert_engine

Unit and integration tests for the Unified Threat Alert Engine.
Verifies alert schemas, evidence building, severity assignment, deduplication, and JSON/CSV persistence.
"""

import sys
import json
import unittest
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.capture.flow_schema import FlowRecord
from src.alerts.alert_schema import ThreatAlert, DetectorResult, ThreatEvidenceItem
from src.alerts.evidence_builder import EvidenceBuilder
from src.alerts.alert_engine import AlertEngine
from src.alerts.alert_writer import AlertWriter
from src.alerts.alert_pipeline import AlertPipeline


class TestAlertEngine(unittest.TestCase):
    """Test suite covering the 12 key requirements for Step 16."""

    def setUp(self):
        self.engine = AlertEngine(mode="AUDIT", suppression_window_seconds=10.0)
        self.engine._suppression_cache.clear()
        self.test_jsonl = project_root / "data/processed/live/alerts/test_alerts.jsonl"
        self.test_csv = project_root / "data/processed/live/alerts/test_alerts.csv"
        self.writer = AlertWriter(jsonl_path=str(self.test_jsonl), csv_path=str(self.test_csv))
        
        self.base_flow = FlowRecord(
            flow_id="flow_alert_test_01",
            src_ip="192.168.0.104",
            dst_ip="104.244.42.1",
            src_port=55000,
            dst_port=443,
            protocol="TCP",
            start_time=1700000000.0,
            last_seen=1700000005.0,
            duration=5.0,
            total_packets=100,
            total_bytes=50000,
            forward_packets=50,
            backward_packets=50,
            forward_bytes=20000,
            backward_bytes=30000,
            packets_per_second=20.0,
            bytes_per_second=10000.0,
            forward_packet_ratio=0.5,
            backward_packet_ratio=0.5,
            forward_byte_ratio=0.4,
            backward_byte_ratio=0.6,
            bytes_per_packet=500.0,
            packets_per_byte=0.002,
            syn_count=1,
            ack_count=99,
            fin_count=1,
            rst_count=0,
            psh_count=15,
            urg_count=0,
            iat_mean=0.05,
            iat_std=0.01,
            iat_min=0.001,
            iat_max=0.10
        )

    def tearDown(self):
        # Clean up temporary test files
        if self.test_jsonl.exists():
            self.test_jsonl.unlink()
        if self.test_csv.exists():
            self.test_csv.unlink()

    def test_01_benign_flow(self):
        """1. Verify benign flow creates BENIGN verdict in AUDIT mode and None in ALERT mode."""
        benign_results = [
            DetectorResult(detector="RandomForest_DDoS", threat_class="DDoS", prediction=0, score=0.01, confidence=0.01),
            DetectorResult(detector="HybridPCA_Botnet_C2", threat_class="BOTNET_C2", prediction=0, score=0.05, confidence=0.05),
            DetectorResult(detector="IsolationForest_PortScan", threat_class="RECON_PORTSCAN", prediction=0, score=-0.12)
        ]
        alert = self.engine.evaluate_detector_results(self.base_flow, benign_results)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, "BENIGN")
        self.assertEqual(alert.threat_class, "BENIGN")
        self.assertIn("Standard telemetry monitoring", alert.recommended_action)

    def test_02_high_ddos_detection(self):
        """2. Verify high DDoS confidence creates CRITICAL/HIGH severity alert."""
        ddos_results = [
            DetectorResult(
                detector="RandomForest_DDoS",
                threat_class="DDoS",
                prediction=1,
                score=0.95,
                confidence=0.95,
                compatible="PARTIALLY_COMPATIBLE",
                evidence=[{"feature": "packets_per_second", "value": 5000.0, "threshold": 100.0, "direction": "above", "explanation": "High packet rate"}]
            )
        ]
        alert = self.engine.evaluate_detector_results(self.base_flow, ddos_results)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "DDoS")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertGreaterEqual(alert.confidence, 0.90)

    def test_03_c2_detection(self):
        """3. Verify Botnet C2 detection creates appropriate alert."""
        c2_results = [
            DetectorResult(
                detector="HybridPCA_Botnet_C2",
                threat_class="BOTNET_C2",
                prediction=1,
                score=0.88,
                confidence=0.88,
                compatible="FULLY_COMPATIBLE",
                evidence=[{"feature": "IAT_Regularity_Causal", "value": 0.92, "threshold": 0.50, "direction": "above", "explanation": "Regular beaconing"}]
            )
        ]
        alert = self.engine.evaluate_detector_results(self.base_flow, c2_results, traffic_context="LAB_ATTACK")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "BOTNET_C2")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.model_status, "FULLY_COMPATIBLE")

    def test_04_portscan_detection(self):
        """4. Verify PortScan reconnaissance creates appropriate alert."""
        ps_results = [
            DetectorResult(
                detector="IsolationForest_PortScan",
                threat_class="RECON_PORTSCAN",
                prediction=1,
                score=0.085,
                confidence=None,
                compatible="PARTIALLY_COMPATIBLE",
                evidence=[{"feature": "portscan_anomaly_score", "value": 0.085, "threshold": 0.026465, "direction": "above", "explanation": "Anomaly score exceeded"}]
            )
        ]
        alert = self.engine.evaluate_detector_results(self.base_flow, ps_results, traffic_context="LAB_ATTACK")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "RECON_PORTSCAN")
        self.assertEqual(alert.severity, "MEDIUM")

    def test_05_multiple_simultaneous_detections(self):
        """5. Verify multiple simultaneous threats trigger MULTI_THREAT CRITICAL alert in LAB_ATTACK."""
        multi_results = [
            DetectorResult(detector="RandomForest_DDoS", threat_class="DDoS", prediction=1, score=0.85, confidence=0.85, compatible="PARTIALLY_COMPATIBLE"),
            DetectorResult(detector="HybridPCA_Botnet_C2", threat_class="BOTNET_C2", prediction=1, score=0.75, confidence=0.75, compatible="FULLY_COMPATIBLE")
        ]
        alert = self.engine.evaluate_detector_results(self.base_flow, multi_results, traffic_context="LAB_ATTACK")
        self.assertIsNotNone(alert)
        self.assertEqual(alert.threat_class, "MULTI_THREAT")
        self.assertEqual(alert.severity, "CRITICAL")

    def test_06_partial_compatibility_disclosure(self):
        """6. Verify partially compatible models disclose status in alert."""
        ev, summary = EvidenceBuilder.build_ddos_evidence(self.base_flow, probability=0.75, model_status="PARTIALLY_COMPATIBLE")
        has_disclosure = any(item.get("feature") == "model_compatibility_disclosure" for item in ev)
        self.assertTrue(has_disclosure, "Partial compatibility disclosure missing from evidence!")

    def test_07_incompatible_detector_handling(self):
        """7. Verify incompatible detector results are ignored and do not trigger false alerts."""
        incompat_results = [
            DetectorResult(detector="ExperimentalModel", threat_class="EXPERIMENTAL", prediction=1, score=0.99, compatible="NOT_COMPATIBLE")
        ]
        alert = self.engine.evaluate_detector_results(self.base_flow, incompat_results)
        self.assertEqual(alert.severity, "BENIGN")

    def test_08_missing_confidence_handling(self):
        """8. Verify detectors without calibrated probabilities preserve confidence=None when score=None."""
        ev, summary = EvidenceBuilder.build_portscan_evidence(self.base_flow, anomaly_score=0.05)
        res = DetectorResult(detector="IsolationForest_PortScan", threat_class="RECON_PORTSCAN", prediction=1, score=None, confidence=None, evidence=ev)
        alert = self.engine.evaluate_detector_results(self.base_flow, [res])
        self.assertIsNone(alert.confidence)

    def test_09_evidence_generation(self):
        """9. Verify evidence contains valid structure (feature, value, threshold, direction, explanation)."""
        c2_dict = {
            "IAT_Regularity_Causal": 0.85,
            "Src_Flows_60s": 12,
            "Src_Flows_BeforeOrAtT": 10,
            "SrcDst_Flows_BeforeOrAtT": 5,
            "RepeatRatio_SrcDst_Causal": 0.70,
            "DstFanoutRatio_Causal": 0.15
        }
        ev, summary = EvidenceBuilder.build_c2_evidence(self.base_flow, c2_dict, score=0.80)
        self.assertGreaterEqual(len(ev), 3)
        for item in ev:
            self.assertIn("feature", item)
            self.assertIn("value", item)
            self.assertIn("explanation", item)

    def test_10_alert_deduplication(self):
        """10. Verify duplicate alerts within suppression window are suppressed."""
        test_engine = AlertEngine(mode="ALERT", suppression_window_seconds=10.0)
        ddos_res = [DetectorResult(detector="RandomForest_DDoS", threat_class="DDoS", prediction=1, score=0.80, confidence=0.80)]

        # First alert allowed
        alert1 = test_engine.evaluate_detector_results(self.base_flow, ddos_res)
        self.assertIsNotNone(alert1)

        # Immediate second alert suppressed
        alert2 = test_engine.evaluate_detector_results(self.base_flow, ddos_res)
        self.assertIsNone(alert2)

    def test_11_severity_assignment(self):
        """11. Verify deterministic severity assignment rules."""
        engine = AlertEngine(mode="AUDIT")
        res_med = [DetectorResult(detector="IsolationForest_PortScan", threat_class="RECON_PORTSCAN", prediction=1, score=0.03)]
        alert_med = engine.evaluate_detector_results(self.base_flow, res_med, traffic_context="LAB_ATTACK")
        self.assertEqual(alert_med.severity, "MEDIUM")

    def test_12_json_and_csv_serialization(self):
        """12. Verify ThreatAlert serializes cleanly to JSON and writes to disk."""
        ddos_res = [DetectorResult(detector="RandomForest_DDoS", threat_class="DDoS", prediction=1, score=0.88, confidence=0.88)]
        alert = self.engine.evaluate_detector_results(self.base_flow, ddos_res, traffic_context="LAB_ATTACK")
        
        # Test JSON string
        json_str = alert.to_json()
        parsed = json.loads(json_str)
        self.assertEqual(parsed["threat_class"], "DDoS")
        self.assertEqual(parsed["severity"], "HIGH")

        # Test AlertWriter
        self.writer.write_alert(alert)
        self.assertTrue(self.test_jsonl.exists())
        self.assertTrue(self.test_csv.exists())


if __name__ == '__main__':
    unittest.main(verbosity=2)
