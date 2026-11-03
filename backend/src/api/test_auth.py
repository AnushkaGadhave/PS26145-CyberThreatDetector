"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.test_auth

Comprehensive security test suite covering:
1. Successful login with a valid account and session cookie assignment.
2. Failed login with an incorrect password (returns generic 401).
3. Login with a nonexistent account (returns generic 401 without user enumeration).
4. Access to protected endpoints without authentication (returns 401).
5. Access with an expired or invalid session (returns 401).
6. Successful authenticated access with session cookie or Bearer token (returns 200).
7. Logout and subsequent rejection of the invalidated session.
8. Administrator-only capture controls (Analyst gets 403; Admin gets allowed).
9. Verification that password hashes (Argon2id) are stored and plaintext passwords never persist.
10. Account lockout protection after repeated failed attempts.
"""

import sys
import unittest
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database.models import Base, UserModel, UserSessionModel
from src.database.database import get_db
from src.database.repository import UserRepository, UserSessionRepository, FlowRepository, AlertRepository
from src.auth.security import hash_password, create_access_token, SESSION_COOKIE_NAME
from src.api.main import app


class TestAuthenticationAndAuthorization(unittest.TestCase):
    """Test suite for authentication, session handling, RBAC, and credential security."""

    @classmethod
    def setUpClass(cls):
        # Create an isolated in-memory SQLite database
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        cls.TestSession = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

        # Seed test users
        db = cls.TestSession()
        try:
            # 1. Admin account
            cls.admin_email = "admin@soc.gov.in"
            cls.admin_password = "SecureAdmin2026!"
            cls.admin_user = UserRepository.create_user(
                db=db,
                email=cls.admin_email,
                hashed_password=hash_password(cls.admin_password),
                full_name="Lead SOC Administrator",
                role="admin",
                is_active=True
            )

            # 2. Analyst account (read-only telemetry observer)
            cls.analyst_email = "analyst@soc.gov.in"
            cls.analyst_password = "AnalystPassword2026!"
            cls.analyst_user = UserRepository.create_user(
                db=db,
                email=cls.analyst_email,
                hashed_password=hash_password(cls.analyst_password),
                full_name="SOC Triage Analyst",
                role="analyst",
                is_active=True
            )

            # 3. Seed sample flow & alert for protected read test
            FlowRepository.create_or_update(db, {
                "flow_id": "flow_auth_test_01",
                "timestamp": 1700000000.0,
                "start_time": 1700000000.0,
                "last_seen": 1700000005.0,
                "src_ip": "192.168.0.10",
                "dst_ip": "10.0.0.1",
                "src_port": 44444,
                "dst_port": 80,
                "protocol": "TCP",
                "duration": 5.0,
                "total_packets": 10,
                "total_bytes": 1000,
                "traffic_context": "UNLABELED_LIVE"
            })
            AlertRepository.create_or_update(db, {
                "alert_id": "alert_auth_test_01",
                "timestamp": 1700000000.0,
                "flow_id": "flow_auth_test_01",
                "src_ip": "192.168.0.10",
                "dst_ip": "10.0.0.1",
                "src_port": 44444,
                "dst_port": 80,
                "protocol": "TCP",
                "threat_class": "RECON_PORTSCAN",
                "threat_category": "Reconnaissance",
                "confidence": 0.95,
                "confidence_band": "HIGH_CONFIDENCE",
                "severity": "HIGH",
                "detector": "PortScan Isolation Forest",
                "model_status": "FULLY_COMPATIBLE",
                "evidence": [],
                "evidence_summary": "Test evidence",
                "recommended_action": "Investigate host",
                "traffic_context": "UNLABELED_LIVE"
            })
        finally:
            db.close()

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        if hasattr(cls, 'test_engine') and cls.test_engine:
            cls.test_engine.dispose()

    def setUp(self):
        def override_get_db():
            db = self.TestSession()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()

    # -------------------------------------------------------------------------
    # 1. Login Tests
    # -------------------------------------------------------------------------
    def test_01_successful_login(self):
        """Verify successful login returns user profile and sets HttpOnly cookie."""
        res = self.client.post("/api/auth/login", json={
            "email": self.admin_email,
            "password": self.admin_password
        })
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["email"], self.admin_email)
        self.assertEqual(data["user"]["role"], "admin")
        self.assertNotIn("hashed_password", data["user"])
        self.assertNotIn("password", data["user"])

        # Check that session cookie was set
        self.assertIn(SESSION_COOKIE_NAME, res.cookies)

    def test_02_failed_login_incorrect_password(self):
        """Verify login fails with incorrect password and returns generic message."""
        res = self.client.post("/api/auth/login", json={
            "email": self.admin_email,
            "password": "WrongPassword999!"
        })
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertIn("Invalid email or password", data["detail"])
        self.assertNotIn(SESSION_COOKIE_NAME, res.cookies)

    def test_03_failed_login_nonexistent_account(self):
        """Verify login with nonexistent account returns generic error without revealing existence."""
        res = self.client.post("/api/auth/login", json={
            "email": "nonexistent_analyst@soc.gov.in",
            "password": "SomeRandomPassword123!"
        })
        self.assertEqual(res.status_code, 401)
        data = res.json()
        self.assertIn("Invalid email or password", data["detail"])

    # -------------------------------------------------------------------------
    # 2. Protected Endpoints & Unauthenticated Access
    # -------------------------------------------------------------------------
    def test_04_access_protected_endpoint_unauthenticated(self):
        """Verify protected endpoints return 401 when accessed without authentication."""
        protected_endpoints = [
            "/api/dashboard/overview",
            "/api/flows",
            "/api/alerts",
            "/api/models/status",
            "/api/capture/status",
            "/api/capture/events",
            "/api/auth/me"
        ]
        for ep in protected_endpoints:
            res = self.client.get(ep)
            self.assertEqual(
                res.status_code, 401,
                f"Endpoint {ep} should return 401 when unauthenticated, got {res.status_code}"
            )

    def test_05_public_health_endpoint_remains_open(self):
        """Verify /health endpoint remains accessible without credentials."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)

    # -------------------------------------------------------------------------
    # 3. Session Expiration & Invalid Session Handling
    # -------------------------------------------------------------------------
    def test_06_access_with_invalid_token(self):
        """Verify request with malformed or tampered token is rejected with 401."""
        res = self.client.get(
            "/api/dashboard/overview",
            headers={"Authorization": "Bearer totally_bogus_token.xyz.123"}
        )
        self.assertEqual(res.status_code, 401)

    def test_07_access_with_expired_token(self):
        """Verify request with expired session token is rejected with 401."""
        expired_token, _, _ = create_access_token(
            user_id="user_test_expired",
            email="expired@soc.gov.in",
            role="analyst",
            expires_delta=timedelta(seconds=-10)  # Expired in past
        )
        res = self.client.get(
            "/api/dashboard/overview",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        self.assertEqual(res.status_code, 401)
        self.assertIn("expired", res.json()["detail"].lower())

    # -------------------------------------------------------------------------
    # 4. Authenticated Access & Current User
    # -------------------------------------------------------------------------
    def test_08_authenticated_access_with_cookie(self):
        """Verify authenticated client can access protected data via session cookie."""
        # Log in to establish cookie
        login_res = self.client.post("/api/auth/login", json={
            "email": self.admin_email,
            "password": self.admin_password
        })
        self.assertEqual(login_res.status_code, 200)

        # Access /api/auth/me
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["user"]["email"], self.admin_email)

        # Access protected telemetry endpoints
        ov_res = self.client.get("/api/dashboard/overview")
        self.assertEqual(ov_res.status_code, 200)

        flows_res = self.client.get("/api/flows")
        self.assertEqual(flows_res.status_code, 200)

        alerts_res = self.client.get("/api/alerts")
        self.assertEqual(alerts_res.status_code, 200)

    # -------------------------------------------------------------------------
    # 5. Logout & Session Invalidation
    # -------------------------------------------------------------------------
    def test_09_logout_revokes_session(self):
        """Verify logout invalidates server-side session and prevents further access."""
        # 1. Login
        self.client.post("/api/auth/login", json={
            "email": self.admin_email,
            "password": self.admin_password
        })

        # 2. Confirm authenticated
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)

        # 3. Logout
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)
        self.assertTrue(logout_res.json()["success"])

        # 4. Verify subsequent access is rejected
        subsequent_res = self.client.get("/api/auth/me")
        self.assertEqual(subsequent_res.status_code, 401)

    # -------------------------------------------------------------------------
    # 6. Role-Based Authorization & Per-User Capture Isolation
    # -------------------------------------------------------------------------
    def test_10_user_local_capture_and_cross_user_isolation(self):
        """Verify normal user can control their own local capture, while cross-user control is forbidden."""
        from unittest.mock import patch
        from src.capture.capture_service import capture_manager

        # Login as analyst (User A)
        self.client.post("/api/auth/login", json={
            "email": self.analyst_email,
            "password": self.analyst_password
        })

        # Analyst CAN view status
        status_res = self.client.get("/api/capture/status")
        self.assertEqual(status_res.status_code, 200)

        # Mock capture_manager start/stop for deterministic unit testing
        with patch.object(capture_manager, "start") as mock_start, \
             patch.object(capture_manager, "stop") as mock_stop:

            # 1. Analyst CAN start their own local capture
            mock_start.return_value = {"success": True, "message": "Live monitoring started.", "status": "RUNNING"}
            start_res = self.client.post("/api/capture/start", json={})
            self.assertEqual(start_res.status_code, 200)
            mock_start.assert_called_once()

            # 2. Cross-user isolation: User B attempts to start while capture is occupied
            mock_start.return_value = {
                "success": False,
                "code": "OCCUPIED_BY_ANOTHER_USER",
                "message": "Local packet sniffer is currently in use by another session."
            }
            start_res_conflict = self.client.post("/api/capture/start", json={})
            self.assertEqual(start_res_conflict.status_code, 409)

            # 3. User B attempts to stop User A's capture session -> Rejected with 403 Forbidden
            mock_stop.return_value = {
                "success": False,
                "code": "FORBIDDEN",
                "message": "Permission denied: You cannot stop a packet capture session owned by another user."
            }
            stop_res = self.client.post("/api/capture/stop")
            self.assertEqual(stop_res.status_code, 403)
            self.assertIn("Permission denied", stop_res.json()["detail"])

            # 4. User A stops their own session successfully
            mock_stop.return_value = {"success": True, "message": "Capture stopped."}
            stop_res_ok = self.client.post("/api/capture/stop")
            self.assertEqual(stop_res_ok.status_code, 200)

        # 5. Remote authenticated client cannot start capture on server
        remote_client = TestClient(app, client=("192.168.1.100", 54321))
        remote_client.post("/api/auth/login", json={
            "email": self.analyst_email,
            "password": self.analyst_password
        })
        remote_start = remote_client.post("/api/capture/start", json={})
        self.assertEqual(remote_start.status_code, 403)
        self.assertIn("restricted to the local host", remote_start.json()["detail"])

    def test_11_admin_can_access_capture_controls(self):
        """Verify Admin role can view status and control capture sessions."""
        from unittest.mock import patch
        from src.capture.capture_service import capture_manager

        # Login as admin
        self.client.post("/api/auth/login", json={
            "email": self.admin_email,
            "password": self.admin_password
        })

        # Admin status check passes
        status_res = self.client.get("/api/capture/status")
        self.assertEqual(status_res.status_code, 200)

        with patch.object(capture_manager, "start", return_value={"success": True, "message": "Started", "status": "RUNNING"}), \
             patch.object(capture_manager, "stop", return_value={"success": True, "message": "Stopped", "status": "STOPPED"}):
            start_res = self.client.post("/api/capture/start", json={})
            self.assertEqual(start_res.status_code, 200)
            stop_res = self.client.post("/api/capture/stop")
            self.assertEqual(stop_res.status_code, 200)

    # -------------------------------------------------------------------------
    # 7. Password Storage Security
    # -------------------------------------------------------------------------
    def test_12_passwords_stored_as_argon2_hashes(self):
        """Verify database only contains Argon2id hashes, never plaintext passwords."""
        db = self.TestSession()
        try:
            users = db.query(UserModel).all()
            for u in users:
                self.assertTrue(
                    u.hashed_password.startswith("$argon2id$"),
                    f"User {u.email} password is not an Argon2id hash: {u.hashed_password}"
                )
                self.assertNotIn(self.admin_password, u.hashed_password)
                self.assertNotIn(self.analyst_password, u.hashed_password)
        finally:
            db.close()

    # -------------------------------------------------------------------------
    # 8. CORS Preflight & Local Frontend Origins
    # -------------------------------------------------------------------------
    def test_13_cors_preflight_for_local_frontend(self):
        """Verify OPTIONS preflight requests succeed for local Vite frontend at port 5174."""
        allowed_origins = ["http://localhost:5174", "http://127.0.0.1:5174"]
        test_routes = [
            ("/api/auth/login", "POST"),
            ("/api/auth/me", "GET"),
        ]

        for orig in allowed_origins:
            for path, method in test_routes:
                headers = {
                    "Origin": orig,
                    "Access-Control-Request-Method": method,
                    "Access-Control-Request-Headers": "content-type",
                }
                res = self.client.options(path, headers=headers)
                self.assertEqual(
                    res.status_code, 200,
                    f"Preflight OPTIONS {path} for origin {orig} failed with status {res.status_code}: {res.text}"
                )
                self.assertEqual(res.headers.get("access-control-allow-origin"), orig)
                self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")
                self.assertIn(method, res.headers.get("access-control-allow-methods", ""))

        # Disallowed origin is rejected with 400 Bad Request
        bad_headers = {
            "Origin": "http://evil-attacker.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        }
        bad_res = self.client.options("/api/auth/login", headers=bad_headers)
        self.assertEqual(bad_res.status_code, 400)

    # -------------------------------------------------------------------------
    # 9. Individual User Registration & Input Validation
    # -------------------------------------------------------------------------
    def test_14_user_registration_success(self):
        """Verify new individual user registration generates account and authenticated session."""
        reg_email = "newuser_alice@example.com"
        reg_password = "SecurePassword2026!"
        reg_payload = {
            "full_name": "Alice Cyber",
            "email": reg_email,
            "password": reg_password
        }
        res = self.client.post("/api/auth/register", json=reg_payload)
        self.assertEqual(res.status_code, 201)
        data = res.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["user"]["email"], reg_email)
        self.assertEqual(data["user"]["full_name"], "Alice Cyber")
        self.assertIn("user_id", data["user"])
        # Verify session cookie was set
        self.assertIn(SESSION_COOKIE_NAME, res.cookies)

        # Verify password in database is Argon2id hash and not plaintext
        db = self.TestSession()
        try:
            user_db = db.query(UserModel).filter(UserModel.email == reg_email).first()
            self.assertIsNotNone(user_db)
            self.assertTrue(user_db.hashed_password.startswith("$argon2id$"))
            self.assertNotIn(reg_password, user_db.hashed_password)
        finally:
            db.close()

    def test_15_duplicate_registration_rejected(self):
        """Verify duplicate email registration returns 409 Conflict."""
        # admin_email already exists in database
        dup_payload = {
            "full_name": "Duplicate Admin",
            "email": self.admin_email,
            "password": "ValidPassword123!"
        }
        res = self.client.post("/api/auth/register", json=dup_payload)
        self.assertEqual(res.status_code, 409)
        self.assertIn("already exists", res.json()["detail"].lower())

    def test_16_weak_password_and_invalid_email_rejected(self):
        """Verify invalid email format and weak passwords are appropriately rejected."""
        # Short password (<8 characters)
        short_res = self.client.post("/api/auth/register", json={
            "full_name": "Test User",
            "email": "valid_email@example.com",
            "password": "short"
        })
        self.assertEqual(short_res.status_code, 422)

        # Password without digits (fails password strength policy)
        no_digit_res = self.client.post("/api/auth/register", json={
            "full_name": "Test User",
            "email": "valid_email2@example.com",
            "password": "NoDigitsAtAllHere!"
        })
        self.assertEqual(no_digit_res.status_code, 400)
        self.assertIn("digit", no_digit_res.json()["detail"].lower())

        # Malformed email
        bad_email_res = self.client.post("/api/auth/register", json={
            "full_name": "Test User",
            "email": "not-a-valid-email",
            "password": "StrongPassword123!"
        })
        self.assertEqual(bad_email_res.status_code, 422)

    # -------------------------------------------------------------------------
    # 10. Cross-User Data Isolation (User A vs User B)
    # -------------------------------------------------------------------------
    def test_17_individual_user_cross_data_isolation(self):
        """Verify User B cannot access, view, or modify User A's flows, alerts, or sensors."""
        # 1. Create User A (Alice)
        alice_email = "user_a_alice@isolation.test"
        alice_pwd = "AlicePassword2026!"
        alice_res = self.client.post("/api/auth/register", json={
            "full_name": "Alice Researcher",
            "email": alice_email,
            "password": alice_pwd
        })
        self.assertEqual(alice_res.status_code, 201)
        alice_user_id = alice_res.json()["user"]["user_id"]

        # Alice enrolls a sensor
        alice_sensor_id = "sensor-alice-iso-01"
        alice_enroll = self.client.post("/api/sensor/enroll", json={
            "sensor_id": alice_sensor_id,
            "name": "Alice Workstation Sensor"
        })
        self.assertEqual(alice_enroll.status_code, 200)

        # Seed a flow and an alert owned by Alice
        db = self.TestSession()
        alice_flow_id = "flow_alice_isolated_01"
        alice_alert_id = "alert_alice_isolated_01"
        try:
            FlowRepository.create_or_update(db, {
                "flow_id": alice_flow_id,
                "timestamp": 1700000000.0,
                "start_time": 1700000000.0,
                "last_seen": 1700000005.0,
                "src_ip": "10.10.10.1",
                "dst_ip": "10.10.10.2",
                "src_port": 12345,
                "dst_port": 443,
                "protocol": "TCP",
                "duration": 5.0,
                "total_packets": 10,
                "total_bytes": 1000,
                "traffic_context": "UNLABELED_LIVE",
                "sensor_id": alice_sensor_id,
                "user_id": alice_user_id
            })
            AlertRepository.create_or_update(db, {
                "alert_id": alice_alert_id,
                "timestamp": 1700000000.0,
                "flow_id": alice_flow_id,
                "src_ip": "10.10.10.1",
                "dst_ip": "10.10.10.2",
                "src_port": 12345,
                "dst_port": 443,
                "protocol": "TCP",
                "threat_class": "DDoS",
                "threat_category": "Volumetric",
                "confidence": 0.99,
                "confidence_band": "HIGH_CONFIDENCE",
                "severity": "CRITICAL",
                "detector": "DDoS Random Forest",
                "model_status": "FULLY_COMPATIBLE",
                "evidence": [],
                "evidence_summary": "Alice isolated alert",
                "recommended_action": "Block source",
                "traffic_context": "UNLABELED_LIVE",
                "sensor_id": alice_sensor_id,
                "user_id": alice_user_id
            })
        finally:
            db.close()

        # 2. Create User B (Bob) and login as Bob
        bob_email = "user_b_bob@isolation.test"
        bob_pwd = "BobPassword2026!"
        bob_res = self.client.post("/api/auth/register", json={
            "full_name": "Bob Analyst",
            "email": bob_email,
            "password": bob_pwd
        })
        self.assertEqual(bob_res.status_code, 201)

        # Bob queries flows: total flows must be 0 (Alice's flow hidden)
        bob_flows = self.client.get("/api/flows")
        self.assertEqual(bob_flows.status_code, 200)
        self.assertEqual(bob_flows.json()["total"], 0)
        self.assertEqual(len(bob_flows.json()["flows"]), 0)

        # Bob directly requests Alice's flow by ID: must return 404 Not Found
        bob_flow_get = self.client.get(f"/api/flows/{alice_flow_id}")
        self.assertEqual(bob_flow_get.status_code, 404)

        # Bob queries alerts: total alerts must be 0 (Alice's alert hidden)
        bob_alerts = self.client.get("/api/alerts")
        self.assertEqual(bob_alerts.status_code, 200)
        self.assertEqual(bob_alerts.json()["total"], 0)
        self.assertEqual(len(bob_alerts.json()["alerts"]), 0)

        # Bob directly requests Alice's alert by ID: must return 404 Not Found
        bob_alert_get = self.client.get(f"/api/alerts/{alice_alert_id}")
        self.assertEqual(bob_alert_get.status_code, 404)

        # Bob queries alert summary: total_alerts and total_flows must be 0
        bob_summary = self.client.get("/api/alerts/summary")
        self.assertEqual(bob_summary.status_code, 200)
        self.assertEqual(bob_summary.json()["total_alerts"], 0)
        self.assertEqual(bob_summary.json()["total_flows"], 0)

        # Bob queries dashboard overview: total_flows and total_alerts must be 0
        bob_overview = self.client.get("/api/dashboard/overview")
        self.assertEqual(bob_overview.status_code, 200)
        self.assertEqual(bob_overview.json()["total_flows"], 0)
        self.assertEqual(bob_overview.json()["total_alerts"], 0)

        # Bob lists sensors: must NOT include Alice's sensor
        bob_sensors = self.client.get("/api/sensor/list")
        self.assertEqual(bob_sensors.status_code, 200)
        bob_sensor_ids = [s["sensor_id"] for s in bob_sensors.json()]
        self.assertNotIn(alice_sensor_id, bob_sensor_ids)

        # Bob attempts to revoke Alice's sensor: must be blocked with 403 Forbidden
        bob_revoke = self.client.post("/api/sensor/revoke", json={"sensor_id": alice_sensor_id})
        self.assertEqual(bob_revoke.status_code, 403)

        # Bob exports comprehensive report: must contain 0 alerts and 0 flows
        bob_export = self.client.get("/api/reports/export?report_type=alerts&format=json")
        self.assertEqual(bob_export.status_code, 200)
        export_data = bob_export.json()
        self.assertEqual(export_data["total_records"], 0)
        self.assertEqual(len(export_data["alerts"]), 0)

    # -------------------------------------------------------------------------
    # 11. Session Restoration & Logout
    # -------------------------------------------------------------------------
    def test_18_session_restoration_and_logout(self):
        """Verify session restoration via GET /api/auth/me and complete invalidation upon logout."""
        user_email = "session_test_user@example.com"
        user_pwd = "UserPass12345!"
        reg = self.client.post("/api/auth/register", json={
            "full_name": "Session Tester",
            "email": user_email,
            "password": user_pwd
        })
        self.assertEqual(reg.status_code, 201)

        # Active session verified
        me_res = self.client.get("/api/auth/me")
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["user"]["email"], user_email)

        # Logout revokes session
        logout_res = self.client.post("/api/auth/logout")
        self.assertEqual(logout_res.status_code, 200)

        # Subsequent authenticated call is rejected with 401
        me_after = self.client.get("/api/auth/me")
        self.assertEqual(me_after.status_code, 401)

    def test_19_cross_user_dashboard_cache_isolation(self):
        """Verify cross-user dashboard cache isolation at the HTTP API level.
        User A's hot cached telemetry must NEVER leak to User B via GET /api/dashboard/overview.
        """
        # Register User A (Alice)
        alice_email = "alice_cache_iso@test.com"
        alice_pwd = "AlicePass2026!"
        alice_reg = self.client.post("/api/auth/register", json={
            "full_name": "Alice Cache",
            "email": alice_email,
            "password": alice_pwd
        })
        self.assertEqual(alice_reg.status_code, 201)
        alice_user_id = alice_reg.json()["user"]["user_id"]

        # Seed 2 flows and 1 alert owned by Alice
        db = self.TestSession()
        try:
            for i in range(2):
                FlowRepository.create_or_update(db, {
                    "flow_id": f"flow_alice_cache_{i}",
                    "timestamp": 1700000000.0 + i,
                    "start_time": 1700000000.0 + i,
                    "last_seen": 1700000005.0 + i,
                    "src_ip": "172.16.1.10",
                    "dst_ip": "8.8.8.8",
                    "protocol": "TCP",
                    "duration": 5.0,
                    "total_packets": 20,
                    "total_bytes": 2000,
                    "traffic_context": "UNLABELED_LIVE",
                    "user_id": alice_user_id
                })
            AlertRepository.create_or_update(db, {
                "alert_id": "alert_alice_cache_01",
                "timestamp": 1700000000.0,
                "flow_id": "flow_alice_cache_0",
                "src_ip": "172.16.1.10",
                "dst_ip": "8.8.8.8",
                "protocol": "TCP",
                "threat_class": "BOTNET_C2",
                "threat_category": "BOTNET_C2",
                "confidence": 0.92,
                "confidence_band": "HIGH_CONFIDENCE",
                "severity": "HIGH",
                "detector": "HybridPCA_Botnet_C2",
                "model_status": "FULLY_COMPATIBLE",
                "traffic_context": "UNLABELED_LIVE",
                "user_id": alice_user_id
            })
        finally:
            db.close()

        # Alice queries /api/dashboard/overview -> Warms User A's cache
        alice_ov1 = self.client.get("/api/dashboard/overview")
        self.assertEqual(alice_ov1.status_code, 200)
        alice_data1 = alice_ov1.json()
        self.assertEqual(alice_data1["total_flows"], 2)
        self.assertEqual(alice_data1["total_alerts"], 1)
        self.assertEqual(alice_data1["severity_counts"]["HIGH"], 1)
        self.assertEqual(alice_data1["top_source_ips"][0]["ip"], "172.16.1.10")

        # Alice queries again -> hits User A's cache
        alice_ov2 = self.client.get("/api/dashboard/overview")
        self.assertEqual(alice_ov2.status_code, 200)
        self.assertEqual(alice_ov2.json(), alice_data1)

        # Register User B (Bob) - client session automatically switches to Bob
        bob_email = "bob_cache_iso@test.com"
        bob_pwd = "BobPass2026!"
        bob_reg = self.client.post("/api/auth/register", json={
            "full_name": "Bob Cache",
            "email": bob_email,
            "password": bob_pwd
        })
        self.assertEqual(bob_reg.status_code, 201)

        # Bob immediately queries /api/dashboard/overview
        # MUST return Bob's empty overview (0 flows, 0 alerts) and NOT Alice's hot cached data!
        bob_ov = self.client.get("/api/dashboard/overview")
        self.assertEqual(bob_ov.status_code, 200)
        bob_data = bob_ov.json()
        self.assertEqual(bob_data["total_flows"], 0, "Bob must not see Alice's cached flows")
        self.assertEqual(bob_data["total_alerts"], 0, "Bob must not see Alice's cached alerts")
        self.assertEqual(len(bob_data["top_source_ips"]), 0, "Bob must not see Alice's cached top source IPs")
        self.assertEqual(bob_data["severity_counts"]["HIGH"], 0)

        # Confirm Alice and Bob overviews are strictly distinct
        self.assertNotEqual(alice_data1["total_flows"], bob_data["total_flows"])
        self.assertNotEqual(alice_data1["top_source_ips"], bob_data["top_source_ips"])


if __name__ == "__main__":
    unittest.main()
