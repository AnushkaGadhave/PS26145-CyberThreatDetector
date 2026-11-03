"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.database.test_database

Unit tests for database schema, ORM models, repositories, and deduplication logic.
Tests against in-memory SQLite or PostgreSQL.
"""

import sys
import time
import unittest
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from src.database.models import Base, FlowModel, AlertModel, ModelStatusModel
from src.database.repository import FlowRepository, AlertRepository, ModelStatusRepository, DashboardRepository


class TestDatabaseLayer(unittest.TestCase):
    """Test suite covering database model operations, CRUD, and deduplication."""

    @classmethod
    def setUpClass(cls):
        # Create an in-memory SQLite database for fast, isolated testing
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        cls.TestSession = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'test_engine') and cls.test_engine:
            cls.test_engine.dispose()

    def setUp(self):
        self.db = self.TestSession()

    def tearDown(self):
        self.db.rollback()
        self.db.close()

    def test_01_table_creation(self):
        """1. Verify that all 3 tables exist in the metadata."""
        table_names = Base.metadata.tables.keys()
        self.assertIn("flows", table_names)
        self.assertIn("alerts", table_names)
        self.assertIn("model_status", table_names)

    def test_02_flow_insert_and_retrieval(self):
        """2. Verify flow insertion and query retrieval."""
        flow_data = {
            "flow_id": "test_flow_sqlite_01",
            "timestamp": 1700000000.0,
            "start_time": 1700000000.0,
            "last_seen": 1700000005.0,
            "src_ip": "192.168.1.50",
            "dst_ip": "1.1.1.1",
            "src_port": 49152,
            "dst_port": 53,
            "protocol": "UDP",
            "duration": 5.0,
            "total_packets": 10,
            "total_bytes": 1200,
            "forward_packets": 5,
            "backward_packets": 5,
            "forward_bytes": 600,
            "backward_bytes": 600,
            "packets_per_second": 2.0,
            "bytes_per_second": 240.0,
            "traffic_context": "UNLABELED_LIVE"
        }
        flow = FlowRepository.create_or_update(self.db, flow_data)
        self.assertIsNotNone(flow.id)
        self.assertEqual(flow.flow_id, "test_flow_sqlite_01")

        # Query back
        retrieved = FlowRepository.get_by_flow_id(self.db, "test_flow_sqlite_01")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.src_ip, "192.168.1.50")
        self.assertEqual(retrieved.dst_ip, "1.1.1.1")

    def test_03_flow_duplicate_prevention(self):
        """3. Verify that re-inserting same flow_id updates instead of creating a duplicate."""
        flow_data = {
            "flow_id": "test_flow_dup_01",
            "timestamp": 1700000000.0,
            "start_time": 1700000000.0,
            "last_seen": 1700000002.0,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "duration": 2.0,
            "total_packets": 4,
            "total_bytes": 500,
            "traffic_context": "UNLABELED_LIVE"
        }
        f1 = FlowRepository.create_or_update(self.db, flow_data)
        initial_id = f1.id

        # Update packet count
        flow_data["total_packets"] = 8
        f2 = FlowRepository.create_or_update(self.db, flow_data)
        self.assertEqual(f2.id, initial_id)
        self.assertEqual(f2.total_packets, 8)

    def test_04_alert_insert_and_retrieval(self):
        """4. Verify alert insertion and query retrieval."""
        alert_data = {
            "alert_id": "test_alert_sqlite_01",
            "timestamp": 1700000000.0,
            "flow_id": "test_flow_sqlite_01",
            "src_ip": "192.168.1.50",
            "dst_ip": "1.1.1.1",
            "src_port": 49152,
            "dst_port": 53,
            "protocol": "UDP",
            "threat_class": "BOTNET_C2",
            "threat_category": "BOTNET_C2",
            "confidence": 0.85,
            "confidence_band": "HIGH_CONFIDENCE",
            "severity": "HIGH",
            "detector": "HybridPCA_Botnet_C2",
            "model_status": "FULLY_COMPATIBLE",
            "evidence": [{"feature": "IAT_Regularity_Causal", "value": 0.88}],
            "evidence_summary": "Botnet C2 heartbeat detected",
            "recommended_action": "Review destination IP in DNS history",
            "traffic_context": "UNLABELED_LIVE"
        }
        alert = AlertRepository.create_or_update(self.db, alert_data)
        self.assertIsNotNone(alert.id)
        self.assertEqual(alert.alert_id, "test_alert_sqlite_01")

        # Query back
        retrieved = AlertRepository.get_by_alert_id(self.db, "test_alert_sqlite_01")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.severity, "HIGH")
        self.assertEqual(retrieved.confidence_band, "HIGH_CONFIDENCE")

    def test_05_alert_duplicate_prevention(self):
        """5. Verify that re-inserting same alert_id updates instead of creating a duplicate."""
        alert_data = {
            "alert_id": "test_alert_dup_01",
            "timestamp": 1700000000.0,
            "flow_id": "test_flow_dup_01",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "protocol": "TCP",
            "threat_class": "RECON_PORTSCAN",
            "threat_category": "RECON_PORTSCAN",
            "severity": "LOW",
            "confidence_band": "LOW_CONFIDENCE",
            "detector": "IsolationForest_PortScan",
            "traffic_context": "UNLABELED_LIVE"
        }
        a1 = AlertRepository.create_or_update(self.db, alert_data)
        initial_id = a1.id

        # Update severity
        alert_data["severity"] = "MEDIUM"
        a2 = AlertRepository.create_or_update(self.db, alert_data)
        self.assertEqual(a2.id, initial_id)
        self.assertEqual(a2.severity, "MEDIUM")

    def test_06_model_status_upsert(self):
        """6. Verify model status seeding and retrieval."""
        rec = ModelStatusRepository.create_or_update(
            db=self.db,
            model_name="DDoS",
            status="PARTIALLY_COMPATIBLE",
            compatible="PARTIALLY_COMPATIBLE",
            reason="Subflow metrics approximated in streaming."
        )
        self.assertIsNotNone(rec.id)
        self.assertEqual(rec.model_name, "DDoS")

        all_models = ModelStatusRepository.get_all(self.db)
        self.assertGreaterEqual(len(all_models), 1)

    def test_07_dashboard_aggregations(self):
        """7. Verify dashboard summary and overview calculations."""
        summary = DashboardRepository.get_alert_summary(self.db)
        self.assertIn("total_alerts", summary)
        self.assertIn("total_flows", summary)
        self.assertIn("low_count", summary)

        overview = DashboardRepository.get_overview(self.db)
        self.assertIn("severity_counts", overview)
        self.assertIn("threat_counts", overview)
        self.assertIn("top_source_ips", overview)

    def test_08_overview_cache(self):
        """8. Verify in-memory TTL caching and cache invalidation for get_overview."""
        DashboardRepository.invalidate_overview_cache()
        o1 = DashboardRepository.get_overview(self.db, user_id="test_user_cache")
        self.assertIsNotNone(o1)

        # Immediate second call should hit the cache
        o2 = DashboardRepository.get_overview(self.db, user_id="test_user_cache")
        self.assertEqual(o1, o2)

        # Invalidation should clear cache cleanly
        DashboardRepository.invalidate_overview_cache(user_id="test_user_cache")
        o3 = DashboardRepository.get_overview(self.db, user_id="test_user_cache")
        self.assertEqual(o1, o3)

    def _seed_alpha_and_beta_data(self):
        """Helper to seed distinct data for User Alpha and User Beta."""
        alpha_id = "user_alpha_iso"
        for i in range(3):
            FlowRepository.create_or_update(self.db, {
                "flow_id": f"flow_alpha_{i}",
                "timestamp": 1700000000.0 + i,
                "start_time": 1700000000.0 + i,
                "last_seen": 1700000005.0 + i,
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.1",
                "protocol": "TCP",
                "duration": 5.0,
                "total_packets": 10,
                "total_bytes": 1000,
                "traffic_context": "UNLABELED_LIVE",
                "user_id": alpha_id
            })
        AlertRepository.create_or_update(self.db, {
            "alert_id": "alert_alpha_01",
            "timestamp": 1700000000.0,
            "flow_id": "flow_alpha_0",
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "threat_class": "DDoS",
            "threat_category": "DDoS",
            "confidence": 0.95,
            "confidence_band": "HIGH_CONFIDENCE",
            "severity": "CRITICAL",
            "detector": "DDoS Detector",
            "traffic_context": "UNLABELED_LIVE",
            "user_id": alpha_id
        })

        beta_id = "user_beta_iso"
        FlowRepository.create_or_update(self.db, {
            "flow_id": "flow_beta_01",
            "timestamp": 1700000100.0,
            "start_time": 1700000100.0,
            "last_seen": 1700000105.0,
            "src_ip": "10.50.0.1",
            "dst_ip": "172.16.0.1",
            "protocol": "UDP",
            "duration": 5.0,
            "total_packets": 5,
            "total_bytes": 500,
            "traffic_context": "UNLABELED_LIVE",
            "user_id": beta_id
        })
        AlertRepository.create_or_update(self.db, {
            "alert_id": "alert_beta_01",
            "timestamp": 1700000100.0,
            "flow_id": "flow_beta_01",
            "src_ip": "10.50.0.1",
            "dst_ip": "172.16.0.1",
            "protocol": "UDP",
            "threat_class": "RECON_PORTSCAN",
            "threat_category": "RECON_PORTSCAN",
            "confidence": 0.85,
            "confidence_band": "MEDIUM_CONFIDENCE",
            "severity": "LOW",
            "detector": "PortScan Detector",
            "traffic_context": "UNLABELED_LIVE",
            "user_id": beta_id
        })

    def test_09_cross_user_cache_isolation(self):
        """9. Verify complete cross-user cache isolation, deep copy mutation defense, and targeted eviction."""
        DashboardRepository.invalidate_overview_cache()
        self._seed_alpha_and_beta_data()
        alpha_id = "user_alpha_iso"
        beta_id = "user_beta_iso"

        # 1. Fetch User Alpha overview -> should reflect Alpha's data only
        alpha_overview = DashboardRepository.get_overview(self.db, user_id=alpha_id)
        self.assertEqual(alpha_overview["total_flows"], 3)
        self.assertEqual(alpha_overview["total_alerts"], 1)
        self.assertEqual(alpha_overview["severity_counts"]["CRITICAL"], 1)
        self.assertEqual(alpha_overview["severity_counts"]["LOW"], 0)
        self.assertEqual(alpha_overview["top_source_ips"][0]["ip"], "192.168.1.100")

        # 2. Fetch User Beta overview -> should reflect Beta's data only (NOT Alpha's cached data)
        beta_overview = DashboardRepository.get_overview(self.db, user_id=beta_id)
        self.assertEqual(beta_overview["total_flows"], 1)
        self.assertEqual(beta_overview["total_alerts"], 1)
        self.assertEqual(beta_overview["severity_counts"]["LOW"], 1)
        self.assertEqual(beta_overview["severity_counts"]["CRITICAL"], 0)
        self.assertEqual(beta_overview["top_source_ips"][0]["ip"], "10.50.0.1")

        # 3. Prove cross-user cache isolation: User Beta cannot receive User Alpha's cached data
        self.assertNotEqual(alpha_overview, beta_overview)
        self.assertNotEqual(alpha_overview["top_source_ips"], beta_overview["top_source_ips"])

        # 4. Immediate re-fetch hits cache, preserving isolation
        alpha_cached = DashboardRepository.get_overview(self.db, user_id=alpha_id)
        beta_cached = DashboardRepository.get_overview(self.db, user_id=beta_id)
        self.assertEqual(alpha_cached["total_flows"], 3)
        self.assertEqual(beta_cached["total_flows"], 1)

        # 5. In-place mutation resistance (deep copy defense)
        alpha_cached["top_source_ips"].append({"ip": "99.99.99.99", "count": 999})
        alpha_recheck = DashboardRepository.get_overview(self.db, user_id=alpha_id)
        self.assertEqual(len(alpha_recheck["top_source_ips"]), 1)
        self.assertNotEqual(alpha_recheck["top_source_ips"][-1]["ip"], "99.99.99.99")

        # 6. Targeted cache invalidation: Alpha is evicted, Beta remains cached
        DashboardRepository.invalidate_overview_cache(user_id=alpha_id)
        from src.database.repository import _OVERVIEW_CACHE
        self.assertNotIn(alpha_id, _OVERVIEW_CACHE)
        self.assertIn(beta_id, _OVERVIEW_CACHE)

    def test_10_concurrent_threads_cross_user_isolation(self):
        """10. Verify concurrent multi-threaded requests remain isolated without race conditions."""
        import concurrent.futures

        DashboardRepository.invalidate_overview_cache()
        self._seed_alpha_and_beta_data()
        alpha_id = "user_alpha_iso"
        beta_id = "user_beta_iso"

        # Warm the cache for both users
        ov_alpha = DashboardRepository.get_overview(self.db, user_id=alpha_id)
        ov_beta = DashboardRepository.get_overview(self.db, user_id=beta_id)
        self.assertEqual(ov_alpha["total_flows"], 3)
        self.assertEqual(ov_beta["total_flows"], 1)

        errors = []

        def worker(uid, expected_flows, expected_ip):
            try:
                for _ in range(10):
                    ov = DashboardRepository.get_overview(self.db, user_id=uid)
                    if ov["total_flows"] != expected_flows:
                        errors.append(f"User {uid} got {ov['total_flows']} flows, expected {expected_flows}")
                    if not ov["top_source_ips"] or ov["top_source_ips"][0]["ip"] != expected_ip:
                        actual_ip = ov["top_source_ips"][0]["ip"] if ov["top_source_ips"] else "None"
                        errors.append(f"User {uid} got IP {actual_ip}, expected {expected_ip}")
                    # Attempt in-place mutation to verify deepcopy protection under concurrency
                    ov["total_flows"] = 999999
                    ov["top_source_ips"].append({"ip": "corrupt_ip", "count": 9999})
            except Exception as e:
                errors.append(str(e))

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            futures = []
            for _ in range(15):
                futures.append(executor.submit(worker, alpha_id, 3, "192.168.1.100"))
                futures.append(executor.submit(worker, beta_id, 1, "10.50.0.1"))
            concurrent.futures.wait(futures)

        self.assertEqual(len(errors), 0, f"Concurrent isolation errors: {errors}")

        # Post-concurrency sanity check: cache remains pristine and isolated
        final_alpha = DashboardRepository.get_overview(self.db, user_id=alpha_id)
        final_beta = DashboardRepository.get_overview(self.db, user_id=beta_id)
        self.assertEqual(final_alpha["total_flows"], 3)
        self.assertEqual(final_beta["total_flows"], 1)
        self.assertEqual(final_alpha["top_source_ips"][0]["ip"], "192.168.1.100")
        self.assertEqual(final_beta["top_source_ips"][0]["ip"], "10.50.0.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
