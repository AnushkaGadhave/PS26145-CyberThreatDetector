"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.detection.test_model_compatibility

Unit tests for runtime feature provenance, causality audit, and model compatibility status.
"""

import sys
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
from src.detection.model_status import get_model_status, is_model_inference_allowed


class TestModelCompatibility(unittest.TestCase):
    """Test suite for feature provenance, causality, and model compatibility verification."""

    @classmethod
    def setUpClass(cls):
        cls.adapter = FeatureAdapter()
        cls.provenance_path = project_root / "evaluation/runtime_feature_provenance.csv"
        cls.distribution_path = project_root / "evaluation/runtime_feature_distribution_comparison.csv"
        cls.report_path = project_root / "evaluation/runtime_model_compatibility_report.txt"

        cls.sample_flow = FlowRecord(
            flow_id="flow_compat_test",
            src_ip="192.168.0.104",
            dst_ip="172.217.115.4",
            src_port=52000,
            dst_port=443,
            protocol="TCP",
            start_time=1700000000.0,
            last_seen=1700000005.0,
            duration=5.0,
            total_packets=50,
            total_bytes=30000,
            forward_packets=25,
            backward_packets=25,
            forward_bytes=10000,
            backward_bytes=20000,
            packets_per_second=10.0,
            bytes_per_second=6000.0,
            forward_packet_ratio=0.5,
            backward_packet_ratio=0.5,
            forward_byte_ratio=0.333333,
            backward_byte_ratio=0.666667,
            bytes_per_packet=600.0,
            packets_per_byte=0.001667,
            syn_count=1,
            ack_count=49,
            fin_count=1,
            rst_count=0,
            psh_count=10,
            urg_count=0,
            iat_mean=0.100,
            iat_std=0.020,
            iat_min=0.005,
            iat_max=0.300
        )

    def test_01_feature_provenance_audit_table(self):
        """Verify provenance table exists and every configured model feature has documented provenance."""
        self.assertTrue(self.provenance_path.exists(), f"Provenance CSV missing at {self.provenance_path}")
        df_prov = pd.read_csv(self.provenance_path)
        
        # Check required columns
        req_cols = [
            'model', 'feature', 'training_source', 'live_source', 'derivation_method',
            'uses_current_flow_only', 'uses_historical_state', 'uses_future_information',
            'directly_observed', 'derived', 'approximated', 'unavailable', 'validation_status', 'notes'
        ]
        for col in req_cols:
            self.assertIn(col, df_prov.columns, f"Required column '{col}' missing from provenance CSV")

        # Total feature count matches model configs
        total_model_features = len(self.adapter.ddos_features) + len(self.adapter.c2_features) + len(self.adapter.portscan_features)
        print(f"\\n[TEST] Audited features in provenance table: {len(df_prov)} (Expected: {total_model_features})")
        self.assertEqual(len(df_prov), total_model_features)

    def test_02_strict_causality_and_no_future_leakage(self):
        """Verify zero features use future information or non-causal operations."""
        df_prov = pd.read_csv(self.provenance_path)
        future_leaks = df_prov[df_prov['uses_future_information'] == True]
        print(f"[TEST] Features with future information leakage: {len(future_leaks)}")
        self.assertEqual(len(future_leaks), 0, "Critical violation: future-dependent features detected!")

    def test_03_no_nan_or_inf_in_live_feature_vectors(self):
        """Verify feature adapter produces 100% finite numerical vectors with exact ordering."""
        # 1. DDoS Vector (74 columns)
        df_ddos = self.adapter.to_ddos_dataframe(self.sample_flow)
        self.assertEqual(list(df_ddos.columns), self.adapter.ddos_features)
        self.assertEqual(df_ddos.isna().sum().sum(), 0)
        self.assertFalse(np.isinf(df_ddos.values).any())

        # 2. C2 Vector (46 columns)
        df_c2 = self.adapter.to_c2_dataframe(self.sample_flow)
        self.assertEqual(list(df_c2.columns), self.adapter.c2_features)
        self.assertEqual(df_c2.isna().sum().sum(), 0)
        self.assertFalse(np.isinf(df_c2.values).any())

        # 3. PortScan Vector (78 columns)
        df_ps = self.adapter.to_portscan_dataframe(self.sample_flow)
        self.assertEqual(list(df_ps.columns), self.adapter.portscan_features)
        self.assertEqual(df_ps.isna().sum().sum(), 0)
        self.assertFalse(np.isinf(df_ps.values).any())
        print("[TEST] All 3 model feature vectors verified: exact ordering, 0 NaN, 0 Inf.")

    def test_04_distribution_comparison_table(self):
        """Verify distribution comparison artifact was created and contains training vs live statistics."""
        self.assertTrue(self.distribution_path.exists(), f"Distribution comparison CSV missing at {self.distribution_path}")
        df_dist = pd.read_csv(self.distribution_path)
        self.assertGreater(len(df_dist), 0)
        print(f"[TEST] Distribution comparison table verified ({len(df_dist)} features compared).")

    def test_05_model_status_api(self):
        """Verify get_model_status API returns structured status for all threat categories."""
        status = get_model_status()
        self.assertIn("ddos", status)
        self.assertIn("c2", status)
        self.assertIn("portscan", status)

        for model_name, info in status.items():
            self.assertIn(info["status"], ["FULLY_COMPATIBLE", "PARTIALLY_COMPATIBLE", "NOT_COMPATIBLE"])
            self.assertIsInstance(info["compatible"], bool)
            self.assertIn("reason", info)
            self.assertTrue(is_model_inference_allowed(model_name))
            print(f"[TEST] Model '{model_name}': Status={info['status']}, Compatible={info['compatible']}")

    def test_06_compatibility_report_file(self):
        """Verify final compatibility report exists."""
        self.assertTrue(self.report_path.exists(), f"Report file missing at {self.report_path}")
        content = self.report_path.read_text(encoding='utf-8')
        self.assertIn("STEP 15: RUNTIME FEATURE PROVENANCE", content)
        self.assertIn("DDoS Detection", content)
        self.assertIn("Botnet C2 Detection", content)
        self.assertIn("Reconnaissance / PortScan Detection", content)


if __name__ == '__main__':
    unittest.main(verbosity=2)
