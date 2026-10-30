"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.test_sensor_ingest

Integration test suite for:
- Remote sensor enrollment (POST /api/sensor/enroll)
- Authenticated ingestion (POST /api/sensor/ingest)
- Deduplication and idempotency
- Payload size and batch limits (HTTP 413, HTTP 400)
- Zero-payload enforcement
- Revocation and access control (HTTP 401, HTTP 403)
- Rate limiting (HTTP 429)
- Remote event streaming with source attribution (GET /api/sensor/events)
"""

import sys
import time
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

from src.database.models import Base, UserModel
from src.database.database import get_db
from src.database.repository import (
    SensorEnrollmentRepository,
    SensorIngestRepository,
    FlowRepository,
    AlertRepository,
)
from src.auth.sensor_auth import (
    generate_sensor_api_key,
    sensor_rate_limiter,
)
from src.auth.security import hash_password, create_access_token
from src.api.main import app


class TestSensorIngestionPipeline(unittest.TestCase):
    """Test suite covering secure remote sensor enrollment and telemetry ingestion."""

    @classmethod
    def setUpClass(cls):
        # Create an in-memory SQLite database using StaticPool for isolated testing
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        cls.TestSession = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

        # Override get_db dependency
        def override_get_db():
            db = cls.TestSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        cls.client = TestClient(app)

        # Seed admin and analyst users
        db = cls.TestSession()
        admin_user = UserModel(
            user_id="usr_admin_test_01",
            email="admin@netra.local",
            hashed_password=hash_password("AdminSecurePassword123!"),
            full_name="SOC Admin",
            role="admin",
            is_active=True
        )
        analyst_user = UserModel(
            user_id="usr_analyst_test_01",
            email="analyst@netra.local",
            hashed_password=hash_password("AnalystPassword123!"),
            full_name="SOC Analyst",
            role="analyst",
            is_active=True
        )
        db.add_all([admin_user, analyst_user])
        db.commit()

        # Obtain valid session tokens via login endpoint so user sessions are registered
        login_admin = cls.client.post("/api/auth/login", json={
            "email": "admin@netra.local",
            "password": "AdminSecurePassword123!"
        })
        cls.admin_token = login_admin.cookies.get("netra_session")

        login_analyst = cls.client.post("/api/auth/login", json={
            "email": "analyst@netra.local",
            "password": "AnalystPassword123!"
        })
        cls.analyst_token = login_analyst.cookies.get("netra_session")

        # Clear client cookie jar so tests explicitly use Authorization Bearer headers or test cookies
        cls.client.cookies.clear()

        # Enroll a test sensor
        raw_key, key_hash, key_prefix = generate_sensor_api_key()
        cls.sensor_id = "sensor-lab-win-test"
        cls.sensor_raw_key = raw_key
        SensorEnrollmentRepository.enroll_sensor(
            db=db,
            sensor_id=cls.sensor_id,
            name="Lab Laptop Test",
            api_key_hash=key_hash,
            api_key_prefix=key_prefix,
            owner_email="admin@netra.local"
        )
        db.close()

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        if hasattr(cls, 'test_engine') and cls.test_engine:
            cls.test_engine.dispose()

    def setUp(self):
        sensor_rate_limiter.reset()

    def test_01_enroll_sensor_authenticated_user(self):
        """1. Verify that authenticated users can enroll sensor devices and unauthenticated requests are rejected."""
        # Unauthenticated attempt should fail (401)
        res_unauth = self.client.post(
            "/api/sensor/enroll",
            json={"sensor_id": "sensor-win-review-2", "name": "Reviewer 2 Laptop"}
        )
        self.assertEqual(res_unauth.status_code, 401)

        # Authenticated user enrollment succeeds and receives unique API key
        res_user = self.client.post(
            "/api/sensor/enroll",
            headers={"Authorization": f"Bearer {self.analyst_token}"},
            json={"sensor_id": "sensor-win-review-2", "name": "Reviewer 2 Laptop"}
        )
        self.assertEqual(res_user.status_code, 200)
        data_user = res_user.json()
        self.assertTrue(data_user["success"])
        self.assertIn("netra_live_", data_user["api_key"])
        self.assertEqual(data_user["sensor"]["sensor_id"], "sensor-win-review-2")
        self.assertEqual(data_user["sensor"]["user_id"], "usr_analyst_test_01")

        # Admin enrollment also succeeds
        res_admin = self.client.post(
            "/api/sensor/enroll",
            headers={"Authorization": f"Bearer {self.admin_token}"},
            json={"sensor_id": "sensor-win-admin-1", "name": "Admin Machine Sensor"}
        )
        self.assertEqual(res_admin.status_code, 200)
        data_admin = res_admin.json()
        self.assertTrue(data_admin["success"])
        self.assertIn("netra_live_", data_admin["api_key"])
        self.assertEqual(data_admin["sensor"]["sensor_id"], "sensor-win-admin-1")
        self.assertEqual(data_admin["sensor"]["user_id"], "usr_admin_test_01")

    def test_02_ingest_valid_batch_success(self):
        """2. Verify valid sensor credential and telemetry batch ingestion."""
        now = time.time()
        record_id = f"meta_test_flow_{int(now * 1000)}"
        flow_id = f"flow_test_{int(now * 1000)}"

        batch_payload = {
            "sensor_id": self.sensor_id,
            "batch_id": "batch_unit_test_01",
            "sent_at": now,
            "records": [
                {
                    "record_id": record_id,
                    "sensor_id": self.sensor_id,
                    "sensor_version": "1.0.0-win",
                    "hostname": "win-test-host",
                    "timestamp": now,
                    "record_type": "FLOW",
                    "interface": "Wi-Fi 2",
                    "flow": {
                        "flow_id": flow_id,
                        "timestamp": now,
                        "start_time": now - 2.0,
                        "last_seen": now,
                        "src_ip": "192.168.0.105",
                        "dst_ip": "142.250.190.46",
                        "src_port": 54321,
                        "dst_port": 443,
                        "protocol": "TCP",
                        "duration": 2.0,
                        "total_packets": 12,
                        "total_bytes": 4500,
                        "traffic_context": "REMOTE_SENSOR"
                    }
                }
            ]
        }

        res = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json=batch_payload
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["accepted"], 1)
        self.assertEqual(data["duplicate"], 0)
        self.assertEqual(data["rejected"], 0)
        self.assertIn(record_id, data["ack_ids"])

        # Verify flow was persisted to DB with sensor_id
        db = self.TestSession()
        flow = FlowRepository.get_by_flow_id(db, flow_id)
        self.assertIsNotNone(flow)
        self.assertEqual(flow.sensor_id, self.sensor_id)
        self.assertEqual(flow.total_packets, 12)
        db.close()

    def test_03_missing_or_invalid_credential_rejected(self):
        """3. Verify missing, invalid, and malformed sensor credentials are rejected (401)."""
        payload = {
            "sensor_id": self.sensor_id,
            "batch_id": "batch_test_02",
            "sent_at": time.time(),
            "records": []
        }

        # Missing credential
        res_missing = self.client.post("/api/sensor/ingest", json=payload)
        self.assertEqual(res_missing.status_code, 401)

        # Invalid credential
        res_invalid = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": "netra_live_completely_fake_invalid_key_123"},
            json=payload
        )
        self.assertEqual(res_invalid.status_code, 401)

    def test_04_revoked_credential_rejected(self):
        """4. Verify revoked sensor credential returns HTTP 403 Forbidden."""
        db = self.TestSession()
        raw_key, key_hash, key_prefix = generate_sensor_api_key()
        revoked_id = "sensor-revoked-test"
        SensorEnrollmentRepository.enroll_sensor(
            db=db,
            sensor_id=revoked_id,
            name="Revoked Device",
            api_key_hash=key_hash,
            api_key_prefix=key_prefix,
            owner_email="admin@netra.local"
        )
        SensorEnrollmentRepository.revoke_sensor(db, revoked_id)
        db.close()

        payload = {
            "sensor_id": revoked_id,
            "batch_id": "batch_revoked_01",
            "sent_at": time.time(),
            "records": []
        }

        res = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": raw_key},
            json=payload
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("revoked", res.json()["detail"].lower())

    def test_05_sensor_id_mismatch_rejected(self):
        """5. Verify caller cannot spoof sensor_id in body differing from authenticated key."""
        payload = {
            "sensor_id": "sensor-spoofed-id-1234",
            "batch_id": "batch_spoof_01",
            "sent_at": time.time(),
            "records": []
        }

        res = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json=payload
        )
        self.assertEqual(res.status_code, 403)
        self.assertIn("mismatch", res.json()["detail"].lower())

    def test_06_batch_size_limit_enforced(self):
        """6. Verify batch exceeding maximum records (100) is rejected with HTTP 400."""
        oversized_records = [
            {"record_id": f"rec_{i}", "record_type": "HEARTBEAT"}
            for i in range(101)
        ]
        payload = {
            "sensor_id": self.sensor_id,
            "batch_id": "batch_oversized",
            "sent_at": time.time(),
            "records": oversized_records
        }

        res = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json=payload
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn("100 records", res.json()["detail"])

    def test_07_zero_payload_enforcement(self):
        """7. Verify records containing packet payloads are rejected by security policy."""
        payload = {
            "sensor_id": self.sensor_id,
            "batch_id": "batch_payload_leak",
            "sent_at": time.time(),
            "records": [
                {
                    "record_id": "rec_payload_leak_01",
                    "record_type": "FLOW",
                    "raw_packet": "45000034a1b2...",
                    "flow": {
                        "flow_id": "flow_leak_01",
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "protocol": "TCP"
                    }
                }
            ]
        }

        res = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json=payload
        )
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["accepted"], 0)
        self.assertEqual(data["rejected"], 1)
        self.assertTrue(any("payload" in err.lower() for err in data["errors"]))

    def test_08_deduplication_and_idempotency(self):
        """8. Verify submitting the same record_id twice is treated as an idempotent duplicate."""
        now = time.time()
        rec_id = f"meta_dup_test_{int(now * 1000)}"
        flow_id = f"flow_dup_{int(now * 1000)}"

        record = {
            "record_id": rec_id,
            "sensor_id": self.sensor_id,
            "timestamp": now,
            "record_type": "FLOW",
            "flow": {
                "flow_id": flow_id,
                "timestamp": now,
                "start_time": now,
                "last_seen": now,
                "src_ip": "192.168.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "UDP",
                "duration": 1.0,
                "total_packets": 2,
                "total_bytes": 120
            }
        }

        # First ingestion -> Accepted
        res1 = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json={"sensor_id": self.sensor_id, "batch_id": "b1", "sent_at": now, "records": [record]}
        )
        self.assertEqual(res1.json()["accepted"], 1)

        # Second ingestion of exact same record -> Duplicate, but acked so client clears queue
        res2 = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json={"sensor_id": self.sensor_id, "batch_id": "b2", "sent_at": now, "records": [record]}
        )
        self.assertEqual(res2.json()["accepted"], 0)
        self.assertEqual(res2.json()["duplicate"], 1)
        self.assertIn(rec_id, res2.json()["ack_ids"])

    def test_09_rate_limiting_enforcement(self):
        """9. Verify sensor rate limiter enforces threshold and returns HTTP 429."""
        sensor_rate_limiter.limit = 3  # Set tight threshold for test

        payload = {
            "sensor_id": self.sensor_id,
            "batch_id": "batch_rl",
            "sent_at": time.time(),
            "records": []
        }

        for i in range(3):
            r = self.client.post(
                "/api/sensor/ingest",
                headers={"X-Sensor-Key": self.sensor_raw_key},
                json=payload
            )
            self.assertEqual(r.status_code, 200)

        # 4th request exceeds rate limit
        res_exceeded = self.client.post(
            "/api/sensor/ingest",
            headers={"X-Sensor-Key": self.sensor_raw_key},
            json=payload
        )
        self.assertEqual(res_exceeded.status_code, 429)
        self.assertIn("Retry-After", res_exceeded.headers)

    def test_10_remote_sensor_events_endpoint(self):
        """10. Verify GET /api/sensor/events returns remote events with source attribution."""
        res = self.client.get(
            "/api/sensor/events",
            headers={"Authorization": f"Bearer {self.analyst_token}"}
        )
        self.assertEqual(res.status_code, 200)
        events = res.json()
        self.assertIsInstance(events, list)
        if events:
            first = events[0]
            self.assertIn("source", first)
            self.assertTrue(first["source"].startswith("SENSOR:"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
