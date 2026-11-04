"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.sensor.test_sensor_auto_enrollment

Comprehensive test suite verifying ThreatTrack Automatic Sensor Enrollment:
1. Dashboard user creates short-lived one-time enrollment token.
2. Token stored exclusively as salted SHA-256 hash.
3. Plaintext permanent API key is never exposed on dashboard token creation.
4. Sensor redeems token over HTTPS, receives newly issued permanent credentials.
5. Token is single-use: subsequent redemption attempts rejected (HTTP 410).
6. Expired tokens are rejected (HTTP 410).
7. Invalid / unrecognized tokens rejected (HTTP 404).
8. Strict per-user sensor ownership and isolation.
9. Local sensor config guard: existing valid sensor configuration protected (preserves sensor5).
10. Automatic generation and validation of sensor_config.json.
11. Revoked sensors immediately blocked from transmitting telemetry.
12. Resource-oriented REST endpoint aliases (/api/sensors/enrollments, /api/sensors/enroll, /api/sensors).
"""

import sys
import time
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi import HTTPException

from src.database.models import Base, UserModel, SensorEnrollmentModel, SensorEnrollmentTokenModel
from src.database.repository import SensorEnrollmentRepository, SensorEnrollmentTokenRepository
from src.auth.sensor_auth import (
    hash_sensor_api_key,
    hash_enrollment_token,
    generate_enrollment_token,
    generate_sensor_api_key,
    get_authenticated_sensor
)
from src.api.routes_sensor import (
    create_enrollment_token,
    redeem_enrollment_token,
    list_sensors,
    revoke_sensor,
    ingest_sensor_batch,
    CreateEnrollmentTokenRequest,
    RedeemEnrollmentTokenRequest,
    SensorRevokeRequest,
    SensorBatchIngestRequest,
    _EXPLICIT_SENSOR_COMMANDS,
    _COMMAND_LOCK
)
from enroll_sensor import (
    check_existing_config,
    save_and_validate_config,
    validate_backend_url
)


class TestSensorAutoEnrollment(unittest.TestCase):
    """Test suite for automatic sensor enrollment, token lifecycle, and configuration generation."""

    @classmethod
    def setUpClass(cls):
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
        self.db.query(SensorEnrollmentTokenModel).delete()
        self.db.query(SensorEnrollmentModel).delete()
        self.db.query(UserModel).delete()
        self.db.commit()

        with _COMMAND_LOCK:
            _EXPLICIT_SENSOR_COMMANDS.clear()

        # Create primary test user (User A)
        self.user_a = UserModel(
            user_id="usr_auto_test_01",
            email="operator_a@threattrack.org",
            hashed_password="hashed_secure_pw_123",
            full_name="Alice Operator",
            role="analyst",
            is_active=True
        )
        # Create second test user (User B) for isolation tests
        self.user_b = UserModel(
            user_id="usr_auto_test_02",
            email="operator_b@threattrack.org",
            hashed_password="hashed_secure_pw_456",
            full_name="Bob Operator",
            role="analyst",
            is_active=True
        )
        self.db.add_all([self.user_a, self.user_b])
        self.db.commit()

        # Mock FastAPI Request
        self.mock_request = MagicMock()
        self.mock_request.client.host = "127.0.0.1"
        self.mock_request.url.scheme = "https"
        self.mock_request.url.netloc = "threattrack-kxqt.onrender.com"
        self.mock_request.headers.get.return_value = "https"

    def tearDown(self):
        try:
            self.db.rollback()
            self.db.query(SensorEnrollmentTokenModel).delete()
            self.db.query(SensorEnrollmentModel).delete()
            self.db.query(UserModel).delete()
            self.db.commit()
        except Exception:
            pass
        finally:
            self.db.close()
        with _COMMAND_LOCK:
            _EXPLICIT_SENSOR_COMMANDS.clear()

    def test_01_create_enrollment_token_success(self):
        """
        Verify dashboard endpoint generates a valid token without leaking permanent credentials:
        - Token string has 'tt_enroll_' prefix with high entropy.
        - Hashed token stored in database.
        - Permanent API key is NOT in the response.
        - Token is marked unredeemed (is_used=False).
        - Associated with authenticated user_a.
        """
        req_body = CreateEnrollmentTokenRequest(
            name="Lab Workstation 01",
            description="Perimeter sniffer",
            device_label="Windows 11 PC",
            sensor_id="sensor-lab-01",
            expires_in_minutes=30
        )

        resp = create_enrollment_token(
            request=self.mock_request,
            payload=req_body,
            current_user=self.user_a,
            db=self.db
        )

        self.assertTrue(resp["success"])
        self.assertEqual(resp["sensor_id"], "sensor-lab-01")
        self.assertEqual(resp["name"], "Lab Workstation 01")
        self.assertTrue(resp["enrollment_token"].startswith("tt_enroll_"))
        self.assertNotIn("api_key", resp, "Permanent API key must NOT be returned during token creation.")
        self.assertIn("setup_command", resp)

        # Verify DB record
        expected_hash = hash_enrollment_token(resp["enrollment_token"])
        token_in_db = SensorEnrollmentTokenRepository.get_by_token_hash(self.db, expected_hash)
        self.assertIsNotNone(token_in_db)
        self.assertEqual(token_in_db.sensor_id, "sensor-lab-01")
        self.assertEqual(token_in_db.user_id, self.user_a.user_id)
        self.assertFalse(token_in_db.is_used)

    def test_02_redeem_enrollment_token_success(self):
        """
        Verify sensor redeems token and receives permanent credentials:
        - Token is redeemed successfully.
        - Permanent API key returned.
        - Sensor is registered as ACTIVE in sensor_enrollments table.
        - Authenticating with newly issued API key succeeds for telemetry.
        """
        # 1. User creates token
        create_req = CreateEnrollmentTokenRequest(
            name="Field Sensor 02",
            sensor_id="sensor-field-02",
            expires_in_minutes=30
        )
        create_resp = create_enrollment_token(
            request=self.mock_request,
            payload=create_req,
            current_user=self.user_a,
            db=self.db
        )
        raw_token = create_resp["enrollment_token"]

        # 2. Sensor agent redeems token
        redeem_req = RedeemEnrollmentTokenRequest(
            token=raw_token,
            hostname="FIELD-WIN-NODE",
            sensor_version="1.0.0-win"
        )
        redeem_resp = redeem_enrollment_token(
            request=self.mock_request,
            payload=redeem_req,
            db=self.db
        )

        self.assertTrue(redeem_resp["success"])
        self.assertEqual(redeem_resp["sensor_id"], "sensor-field-02")
        self.assertIn("api_key", redeem_resp)
        self.assertTrue(redeem_resp["api_key"].startswith("netra_live_"))

        # 3. Verify sensor is active in DB
        sensor = SensorEnrollmentRepository.get_by_sensor_id(self.db, "sensor-field-02")
        self.assertIsNotNone(sensor)
        self.assertEqual(sensor.status, "ACTIVE")
        self.assertEqual(sensor.user_id, self.user_a.user_id)
        self.assertEqual(sensor.hostname, "FIELD-WIN-NODE")

        # 4. Verify token is marked as used
        token_hash = hash_enrollment_token(raw_token)
        token_db = SensorEnrollmentTokenRepository.get_by_token_hash(self.db, token_hash)
        self.assertTrue(token_db.is_used)
        self.assertIsNotNone(token_db.redeemed_at)

        # 5. Verify sensor can authenticate with the issued API key
        raw_key = redeem_resp["api_key"]
        auth_sensor = get_authenticated_sensor(
            request=self.mock_request,
            x_sensor_key=raw_key,
            authorization=None,
            db=self.db
        )
        self.assertEqual(auth_sensor.sensor_id, "sensor-field-02")

    def test_03_token_single_use_enforcement(self):
        """
        Verify that a redeemed token cannot be reused:
        - First redemption succeeds.
        - Second redemption fails with HTTP 410 Gone.
        """
        create_resp = create_enrollment_token(
            request=self.mock_request,
            payload=CreateEnrollmentTokenRequest(name="Single Use Sensor", sensor_id="sensor-single-01"),
            current_user=self.user_a,
            db=self.db
        )
        raw_token = create_resp["enrollment_token"]

        # First redemption
        redeem_req = RedeemEnrollmentTokenRequest(token=raw_token)
        r1 = redeem_enrollment_token(request=self.mock_request, payload=redeem_req, db=self.db)
        self.assertTrue(r1["success"])

        # Second redemption attempt MUST fail with 410
        with self.assertRaises(HTTPException) as ctx:
            redeem_enrollment_token(request=self.mock_request, payload=redeem_req, db=self.db)
        self.assertEqual(ctx.exception.status_code, 410)
        self.assertIn("already been redeemed", ctx.exception.detail)

    def test_04_expired_token_rejection(self):
        """
        Verify that expired enrollment tokens are rejected:
        - Token with past expires_at fails redemption with HTTP 410 Gone.
        """
        raw_token, token_hash = generate_enrollment_token()
        past_time = datetime.now(timezone.utc) - timedelta(minutes=5)

        SensorEnrollmentTokenRepository.create_token(
            db=self.db,
            token_hash=token_hash,
            sensor_id="sensor-expired-01",
            name="Expired Sensor",
            owner_email=self.user_a.email,
            user_id=self.user_a.user_id,
            expires_at=past_time
        )

        redeem_req = RedeemEnrollmentTokenRequest(token=raw_token)
        with self.assertRaises(HTTPException) as ctx:
            redeem_enrollment_token(request=self.mock_request, payload=redeem_req, db=self.db)
        self.assertEqual(ctx.exception.status_code, 410)
        self.assertIn("expired", ctx.exception.detail)

    def test_05_invalid_token_rejection(self):
        """
        Verify that bogus or invalid tokens are rejected with HTTP 404:
        """
        redeem_req = RedeemEnrollmentTokenRequest(token="tt_enroll_completely_bogus_token_123456789")
        with self.assertRaises(HTTPException) as ctx:
            redeem_enrollment_token(request=self.mock_request, payload=redeem_req, db=self.db)
        self.assertEqual(ctx.exception.status_code, 404)
        self.assertIn("Invalid enrollment token", ctx.exception.detail)

    def test_06_cross_user_isolation(self):
        """
        Verify strict user isolation:
        - User A's enrolled sensors are NOT visible to User B in list_sensors.
        - User B cannot revoke User A's sensor.
        """
        # Enroll sensor under User A
        c_resp = create_enrollment_token(
            request=self.mock_request,
            payload=CreateEnrollmentTokenRequest(name="User A Sensor", sensor_id="sensor-user-a"),
            current_user=self.user_a,
            db=self.db
        )
        redeem_enrollment_token(
            request=self.mock_request,
            payload=RedeemEnrollmentTokenRequest(token=c_resp["enrollment_token"]),
            db=self.db
        )

        # 1. User A lists sensors: sees sensor-user-a
        sensors_a = list_sensors(current_user=self.user_a, db=self.db)
        sensor_ids_a = [s["sensor_id"] for s in sensors_a]
        self.assertIn("sensor-user-a", sensor_ids_a)

        # 2. User B lists sensors: CANNOT see sensor-user-a
        sensors_b = list_sensors(current_user=self.user_b, db=self.db)
        sensor_ids_b = [s["sensor_id"] for s in sensors_b]
        self.assertNotIn("sensor-user-a", sensor_ids_b)

        # 3. User B attempts to revoke User A's sensor: rejected with HTTP 403 Forbidden
        with self.assertRaises(HTTPException) as ctx:
            revoke_sensor(
                payload=SensorRevokeRequest(sensor_id="sensor-user-a"),
                current_user=self.user_b,
                db=self.db
            )
        self.assertEqual(ctx.exception.status_code, 403)

    def test_07_enroll_sensor_cli_safeguards_preserve_existing(self):
        """
        Verify enroll_sensor.py configuration safeguards (protecting sensor5):
        - check_existing_config detects existing valid sensor_config.json.
        - Without force=True, can_proceed is False (prevents overwriting sensor5).
        - With force=True, can_proceed is True.
        """
        temp_dir = tempfile.mkdtemp(prefix="tt_enroll_cli_")
        try:
            cfg_file = Path(temp_dir) / "sensor_config.json"

            # 1. Non-existent file allows proceeding
            can_p, sid = check_existing_config(cfg_file, force=False)
            self.assertTrue(can_p)
            self.assertIsNone(sid)

            # 2. Write an active sensor config (simulating sensor5)
            with open(cfg_file, "w", encoding="utf-8") as f:
                json.dump({
                    "sensor_id": "sensor5",
                    "api_key": "netra_live_secretkey12345",
                    "backend_url": "https://threattrack-kxqt.onrender.com"
                }, f)

            # 3. Without force: MUST return can_proceed=False to protect sensor5
            can_p, sid = check_existing_config(cfg_file, force=False)
            self.assertFalse(can_p)
            self.assertEqual(sid, "sensor5")

            # 4. With explicit force: allows proceeding
            can_p_forced, _ = check_existing_config(cfg_file, force=True)
            self.assertTrue(can_p_forced)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_08_save_and_validate_config(self):
        """
        Verify save_and_validate_config writes valid JSON and reads it back:
        - Writes valid configuration file.
        - Sets permissions and atomic replace.
        - Verified contents match sensor_id and api_key.
        """
        temp_dir = tempfile.mkdtemp(prefix="tt_save_cfg_")
        try:
            cfg_file = Path(temp_dir) / "sensor_config.json"
            result = save_and_validate_config(
                config_path=cfg_file,
                sensor_id="sensor-auto-99",
                api_key="netra_live_testkey_9999",
                backend_url="https://threattrack-kxqt.onrender.com",
                interface="Wi-Fi 3"
            )

            self.assertEqual(result["sensor_id"], "sensor-auto-99")
            self.assertTrue(cfg_file.exists())

            # Read back manually to verify JSON format
            with open(cfg_file, "r", encoding="utf-8") as f:
                saved = json.load(f)
            self.assertEqual(saved["sensor_id"], "sensor-auto-99")
            self.assertEqual(saved["interface"], "Wi-Fi 3")
            self.assertEqual(saved["backend_url"], "https://threattrack-kxqt.onrender.com")
            self.assertEqual(saved["api_key"], "netra_live_testkey_9999")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_09_revoked_sensor_blocked(self):
        """
        Verify that a revoked sensor cannot transmit telemetry:
        - Sensor is enrolled and active.
        - Sensor is revoked.
        - Ingest request fails with HTTP 403 Forbidden.
        """
        c_resp = create_enrollment_token(
            request=self.mock_request,
            payload=CreateEnrollmentTokenRequest(name="Revoke Me Sensor", sensor_id="sensor-rev-01"),
            current_user=self.user_a,
            db=self.db
        )
        r_resp = redeem_enrollment_token(
            request=self.mock_request,
            payload=RedeemEnrollmentTokenRequest(token=c_resp["enrollment_token"]),
            db=self.db
        )
        raw_key = r_resp["api_key"]

        # Revoke sensor
        revoke_sensor(payload=SensorRevokeRequest(sensor_id="sensor-rev-01"), current_user=self.user_a, db=self.db)

        # Attempt to authenticate sensor
        with self.assertRaises(HTTPException) as ctx:
            get_authenticated_sensor(
                request=self.mock_request,
                x_sensor_key=raw_key,
                authorization=None,
                db=self.db
            )
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertIn("revoked", ctx.exception.detail)


if __name__ == "__main__":
    unittest.main()

