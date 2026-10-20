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
from src.database.models import Base, FlowModel, AlertModel, ModelStatusModel
from src.database.repository import FlowRepository, AlertRepository, ModelStatusRepository, DashboardRepository


class TestDatabaseLayer(unittest.TestCase):
    """Test suite covering database model operations, CRUD, and deduplication."""

    @classmethod
    def setUpClass(cls):
        # Create an in-memory SQLite database for fast, isolated testing
        cls.test_engine = create_engine("sqlite:///:memory:", echo=False)
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
