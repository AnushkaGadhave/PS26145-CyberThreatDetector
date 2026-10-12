import sys
import json
import unittest
from pathlib import Path
import numpy as np
import pandas as pd

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.capture.flow_schema import FlowRecord
from src.detection.feature_adapter import FeatureAdapter
from src.detection.threat_detector import ThreatDetector, ThreatAlert


class TestDetectionPipeline(unittest.TestCase):
    """Test suite for live feature adaptation and multi-threat inference."""

    @classmethod
    def setUpClass(cls):
        cls.adapter = FeatureAdapter()
        cls.detector = ThreatDetector(
            alerts_jsonl_path="data/processed/live/test_alerts.jsonl"
        )
        
        # Synthetic sample flow
        cls.sample_flow = FlowRecord(
            flow_id="flow_tcp_test12345",
            src_ip="192.168.0.104",
            dst_ip="172.64.155.209",
            src_port=56994,
            dst_port=443,
            protocol="TCP",
            start_time=1700000000.0,
            last_seen=1700000008.89,
            duration=8.89,
            total_packets=186,
            total_bytes=101294,
            forward_packets=92,
            backward_packets=94,
            forward_bytes=45000,
            backward_bytes=56294,
            packets_per_second=20.92,
            bytes_per_second=11394.15,
            forward_packet_ratio=0.4946,
            backward_packet_ratio=0.5054,
            forward_byte_ratio=0.4442,
            backward_byte_ratio=0.5558,
            bytes_per_packet=544.59,
            packets_per_byte=0.001836,
            syn_count=1,
            ack_count=185,
            fin_count=2,
            rst_count=0,
            psh_count=24,
            urg_count=0,
            iat_mean=0.048,
            iat_std=0.012,
            iat_min=0.001,
            iat_max=0.250
        )

    def test_01_feature_adapter_ddos(self):
        """Verify feature adapter produces valid 74-column vector for DDoS model."""
        df_ddos = self.adapter.to_ddos_dataframe(self.sample_flow)
        print(f"\\n[TEST] DDoS feature vector shape: {df_ddos.shape}")
        self.assertEqual(df_ddos.shape, (1, 74))
        self.assertEqual(df_ddos.isna().sum().sum(), 0)
        self.assertFalse(np.isinf(df_ddos.values).any())

    def test_02_feature_adapter_portscan(self):
        """Verify feature adapter produces valid 78-column vector for PortScan model."""
        df_ps = self.adapter.to_portscan_dataframe(self.sample_flow)
        print(f"[TEST] PortScan feature vector shape: {df_ps.shape}")
        self.assertEqual(df_ps.shape, (1, 78))
        self.assertEqual(df_ps.isna().sum().sum(), 0)
        self.assertFalse(np.isinf(df_ps.values).any())

    def test_03_feature_adapter_c2(self):
        """Verify feature adapter produces valid 46-column vector for C2 model."""
        df_c2 = self.adapter.to_c2_dataframe(self.sample_flow)
        print(f"[TEST] C2 feature vector shape: {df_c2.shape}")
        self.assertEqual(df_c2.shape, (1, 46))
        self.assertEqual(df_c2.isna().sum().sum(), 0)
        self.assertFalse(np.isinf(df_c2.values).any())

    def test_04_threat_detector_inference(self):
        """Verify end-to-end multi-threat detection on sample flow."""
        alert = self.detector.evaluate_flow(self.sample_flow)
        print(f"[TEST] Detection Alert Verdict: {alert.threat_level} (Threats: {alert.detected_threats})")
        print(f"       DDoS: prob={alert.ddos_probability:.4f}, pred={alert.ddos_prediction}")
        print(f"       PortScan: score={alert.portscan_anomaly_score:.6f}, pred={alert.portscan_prediction}")
        print(f"       C2: prob={alert.c2_probability:.4f}, pred={alert.c2_prediction}")

        self.assertIsInstance(alert, ThreatAlert)
        self.assertIn(alert.threat_level, ["BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self.assertIsInstance(alert.detected_threats, list)

    def test_05_evaluate_captured_live_flows(self):
        """Verify detection pipeline on real flows captured from live Wi-Fi traffic."""
        jsonl_path = project_root / "data/processed/live/live_flows.jsonl"
        if not jsonl_path.exists():
            self.skipTest("Live flows JSONL not found")

        flows_evaluated = 0
        with open(jsonl_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    record = FlowRecord.from_dict(json.loads(line.strip()))
                    alert = self.detector.evaluate_flow(record)
                    flows_evaluated += 1

        print(f"[TEST] Successfully evaluated {flows_evaluated} real live flows from {jsonl_path}")
        self.assertGreater(flows_evaluated, 0)

        # Cleanup temporary test alerts file
        test_alerts = project_root / "data/processed/live/test_alerts.jsonl"
        if test_alerts.exists():
            test_alerts.unlink()


if __name__ == '__main__':
    unittest.main(verbosity=2)
