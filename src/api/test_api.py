"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.test_api

Integration and endpoint tests for FastAPI backend using FastAPI TestClient.
Tests all endpoints, query filtering, pagination, 404 handling, and data contract compliance.
"""

import sys
import unittest
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database.models import Base
from src.database.database import get_db
from src.database.repository import FlowRepository, AlertRepository, ModelStatusRepository
from src.api.main import app


class TestFastAPIBackend(unittest.TestCase):
    """Test suite covering all FastAPI REST endpoints and response schemas."""

    @classmethod
    def setUpClass(cls):
        # Create an in-memory SQLite database for isolated API tests with StaticPool
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        cls.TestSession = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

        # Populate test fixtures
        db = cls.TestSession()
        try:
            # Seed 2 test flows
            FlowRepository.create_or_update(db, {
                "flow_id": "flow_test_api_01",
                "timestamp": 1700000000.0,
                "start_time": 1700000000.0,
                "last_seen": 1700000005.0,
                "src_ip": "192.168.0.104",
                "dst_ip": "172.217.115.4",
                "src_port": 51835,
                "dst_port": 443,
                "protocol": "TCP",
                "duration": 5.0,
                "total_packets": 20,
                "total_bytes": 2500,
                "traffic_context": "UNLABELED_LIVE"
            })
            FlowRepository.create_or_update(db, {
                "flow_id": "flow_test_api_02",
                "timestamp": 1700000010.0,
                "start_time": 1700000010.0,
                "last_seen": 1700000011.0,
                "src_ip": "192.168.0.104",
                "dst_ip": "1.1.1.1",
                "src_port": 60000,
                "dst_port": 53,
                "protocol": "UDP",
                "duration": 1.0,
                "total_packets": 2,
                "total_bytes": 200,
                "traffic_context": "UNLABELED_LIVE"
            })

            # Seed 2 test alerts
            AlertRepository.create_or_update(db, {
                "alert_id": "alert_test_api_01",
                "timestamp": 1700000000.0,
                "flow_id": "flow_test_api_01",
                "src_ip": "192.168.0.104",
                "dst_ip": "172.217.115.4",
                "src_port": 51835,
                "dst_port": 443,
                "protocol": "TCP",
                "threat_class": "RECON_PORTSCAN",
                "threat_category": "RECON_PORTSCAN",
                "confidence": 0.08,
                "confidence_band": "LOW_CONFIDENCE",
                "severity": "LOW",
                "detector": "IsolationForest_PortScan",
                "model_status": "PARTIALLY_COMPATIBLE",
                "evidence": [{"feature": "portscan_anomaly_score", "value": 0.08}],
                "evidence_summary": "Reconnaissance anomaly exceeding baseline",
                "recommended_action": "Review source IP connection patterns",
                "traffic_context": "UNLABELED_LIVE"
            })
            AlertRepository.create_or_update(db, {
                "alert_id": "alert_test_api_02",
                "timestamp": 1700000010.0,
                "flow_id": "flow_test_api_02",
                "src_ip": "192.168.0.104",
                "dst_ip": "1.1.1.1",
                "src_port": 60000,
                "dst_port": 53,
                "protocol": "UDP",
                "threat_class": "BOTNET_C2",
                "threat_category": "BOTNET_C2",
                "confidence": 0.90,
                "confidence_band": "HIGH_CONFIDENCE",
                "severity": "HIGH",
                "detector": "HybridPCA_Botnet_C2",
                "model_status": "FULLY_COMPATIBLE",
                "evidence": [{"feature": "IAT_Regularity_Causal", "value": 0.95}],
                "evidence_summary": "Botnet C2 heartbeat detected",
                "recommended_action": "Review destination IP in DNS history",
                "traffic_context": "UNLABELED_LIVE"
            })

            # Seed model status
            ModelStatusRepository.create_or_update(
                db, "DDoS", "PARTIALLY_COMPATIBLE", "PARTIALLY_COMPATIBLE", "Subflow metrics approximated."
            )
            ModelStatusRepository.create_or_update(
                db, "BOTNET_C2", "FULLY_COMPATIBLE", "FULLY_COMPATIBLE", "Causal rolling features compatible."
            )
            ModelStatusRepository.create_or_update(
                db, "RECON_PORTSCAN", "PARTIALLY_COMPATIBLE", "PARTIALLY_COMPATIBLE", "Single flow isolation."
            )
        finally:
            db.close()

        # Override get_db dependency for TestClient
        def override_get_db():
            db = cls.TestSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()

    def test_01_health_endpoint(self):
        """1. Test GET /health endpoint."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "PS26145 API")

    def test_02_get_flows_paginated(self):
        """2. Test GET /api/flows with pagination and filtering."""
        res = self.client.get("/api/flows?limit=10&offset=0")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total", data)
        self.assertIn("flows", data)
        self.assertEqual(data["total"], 2)
        self.assertEqual(len(data["flows"]), 2)

        # Filter by protocol
        res_udp = self.client.get("/api/flows?protocol=UDP")
        self.assertEqual(res_udp.status_code, 200)
        data_udp = res_udp.json()
        self.assertEqual(data_udp["total"], 1)
        self.assertEqual(data_udp["flows"][0]["protocol"], "UDP")

    def test_03_get_flow_by_id(self):
        """3. Test GET /api/flows/{flow_id} success and 404."""
        res = self.client.get("/api/flows/flow_test_api_01")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["flow_id"], "flow_test_api_01")
        self.assertEqual(data["src_ip"], "192.168.0.104")

        # 404 test
        res_404 = self.client.get("/api/flows/non_existent_flow_id")
        self.assertEqual(res_404.status_code, 404)
        self.assertIn("detail", res_404.json())

    def test_04_get_alerts_paginated(self):
        """4. Test GET /api/alerts with pagination and severity filtering."""
        res = self.client.get("/api/alerts?limit=10&offset=0")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total", data)
        self.assertIn("alerts", data)
        self.assertEqual(data["total"], 2)

        # Filter by severity
        res_high = self.client.get("/api/alerts?severity=HIGH")
        self.assertEqual(res_high.status_code, 200)
        data_high = res_high.json()
        self.assertEqual(data_high["total"], 1)
        self.assertEqual(data_high["alerts"][0]["threat_class"], "BOTNET_C2")

    def test_05_get_alert_by_id(self):
        """5. Test GET /api/alerts/{alert_id} success and 404."""
        res = self.client.get("/api/alerts/alert_test_api_01")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["alert_id"], "alert_test_api_01")
        self.assertEqual(data["traffic_context"], "UNLABELED_LIVE")
        self.assertIn("evidence", data)

        # 404 test
        res_404 = self.client.get("/api/alerts/non_existent_alert_id")
        self.assertEqual(res_404.status_code, 404)

    def test_06_get_recent_alerts(self):
        """6. Test GET /api/alerts/recent for live polling."""
        res = self.client.get("/api/alerts/recent?limit=10")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)
        # Newest first
        self.assertGreaterEqual(data[0]["timestamp"], data[1]["timestamp"])

    def test_07_get_alert_summary(self):
        """7. Test GET /api/alerts/summary."""
        res = self.client.get("/api/alerts/summary")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["total_alerts"], 2)
        self.assertEqual(data["total_flows"], 2)
        self.assertEqual(data["high_count"], 1)
        self.assertEqual(data["low_count"], 1)
        self.assertEqual(data["botnet_c2_count"], 1)
        self.assertEqual(data["recon_portscan_count"], 1)
        self.assertEqual(data["unlabeled_live_alerts"], 2)

    def test_08_get_model_statuses(self):
        """8. Test GET /api/models/status."""
        res = self.client.get("/api/models/status")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 3)
        model_names = [m["model_name"] for m in data]
        self.assertIn("DDoS", model_names)
        self.assertIn("BOTNET_C2", model_names)
        self.assertIn("RECON_PORTSCAN", model_names)

    def test_09_get_dashboard_overview(self):
        """9. Test GET /api/dashboard/overview."""
        res = self.client.get("/api/dashboard/overview")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("total_flows", data)
        self.assertIn("total_alerts", data)
        self.assertIn("severity_counts", data)
        self.assertIn("threat_counts", data)
        self.assertIn("top_source_ips", data)
        self.assertIn("top_destination_ips", data)
        self.assertIn("protocol_counts", data)
        self.assertIn("model_status", data)

    def test_10_invalid_query_parameters(self):
        """10. Test validation error handling on invalid query parameters."""
        res = self.client.get("/api/flows?limit=-5")
        self.assertEqual(res.status_code, 422)  # Unprocessable Entity for Pydantic validation

        res_time = self.client.get("/api/alerts?start_time=2000&end_time=1000")
        self.assertEqual(res_time.status_code, 400)


if __name__ == "__main__":
    unittest.main(verbosity=2)
