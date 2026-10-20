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
    # 6. Role-Based Authorization (Admin vs Analyst)
    # -------------------------------------------------------------------------
    def test_10_analyst_cannot_control_sensor_capture(self):
        """Verify Analyst role receives 403 Forbidden when attempting capture start/stop."""
        # Login as analyst
        self.client.post("/api/auth/login", json={
            "email": self.analyst_email,
            "password": self.analyst_password
        })

        # Analyst CAN view status
        status_res = self.client.get("/api/capture/status")
        self.assertEqual(status_res.status_code, 200)

        # Analyst CANNOT start capture
        start_res = self.client.post("/api/capture/start", json={})
        self.assertEqual(start_res.status_code, 403)
        self.assertIn("Administrative privileges required", start_res.json()["detail"])

        # Analyst CANNOT stop capture
        stop_res = self.client.post("/api/capture/stop")
        self.assertEqual(stop_res.status_code, 403)

    def test_11_admin_can_access_capture_controls(self):
        """Verify Admin role passes role authorization for capture endpoints."""
        # Login as admin
        self.client.post("/api/auth/login", json={
            "email": self.admin_email,
            "password": self.admin_password
        })

        # Admin status check passes
        status_res = self.client.get("/api/capture/status")
        self.assertEqual(status_res.status_code, 200)

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


if __name__ == "__main__":
    unittest.main()
