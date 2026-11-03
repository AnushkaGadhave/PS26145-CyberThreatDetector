"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.test_cors

Comprehensive CORS verification test suite:
- Production Vercel origin validation (https://threattrack.vercel.app)
- Credential support (access-control-allow-credentials: true) for HttpOnly session cookies
- OPTIONS preflight request verification
- Subdomain matching via CORS_ORIGIN_REGEX (https://*.vercel.app)
- Disallowed external origin rejection
- Preservation of CORS headers on error responses (401 Unauthorized, 500 Internal Error)
"""

import sys
import unittest
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient
from src.api.main import app

PROD_ORIGIN = "https://threattrack.vercel.app"


class TestCORSConfiguration(unittest.TestCase):
    """Test suite verifying defense-grade CORS compliance for production frontend deployment."""

    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app, raise_server_exceptions=False)

    def test_01_get_health_cors_headers(self):
        """Verify GET /health returns Allow-Origin and Allow-Credentials for production Vercel frontend."""
        res = self.client.get("/health", headers={"Origin": PROD_ORIGIN})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
        self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")
        self.assertEqual(res.headers.get("access-control-expose-headers"), "Content-Disposition")

    def test_02_options_preflight_health(self):
        """Verify OPTIONS preflight request on /health succeeds with 200 and permits methods/headers."""
        res = self.client.options(
            "/health",
            headers={
                "Origin": PROD_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
        self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")
        self.assertIn("GET", res.headers.get("access-control-allow-methods", ""))
        self.assertIn("content-type", res.headers.get("access-control-allow-headers", "").lower())

    def test_03_options_preflight_login(self):
        """Verify OPTIONS preflight on POST /api/auth/login allows credentials and Content-Type."""
        res = self.client.options(
            "/api/auth/login",
            headers={
                "Origin": PROD_ORIGIN,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
        self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")
        self.assertIn("POST", res.headers.get("access-control-allow-methods", ""))

    def test_04_vercel_preview_subdomain_cors(self):
        """Verify dynamic Vercel preview environments (*.vercel.app) are allowed via regex."""
        preview_origin = "https://threattrack-git-preview-soc.vercel.app"
        res = self.client.get("/health", headers={"Origin": preview_origin})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("access-control-allow-origin"), preview_origin)
        self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")

    def test_05_disallowed_origin_rejected(self):
        """Verify untrusted external domains do not receive Access-Control-Allow-Origin header."""
        malicious_origin = "https://malicious-attacker-domain.com"
        res = self.client.get("/health", headers={"Origin": malicious_origin})
        self.assertEqual(res.status_code, 200)
        self.assertNotIn("access-control-allow-origin", res.headers)

    def test_06_unauthorized_error_preserves_cors(self):
        """Verify 401 Unauthorized responses (e.g. unauthenticated /api/auth/me) preserve CORS headers."""
        res = self.client.get("/api/auth/me", headers={"Origin": PROD_ORIGIN})
        self.assertEqual(res.status_code, 401)
        self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
        self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")

    def test_07_server_error_500_preserves_cors(self):
        """Verify 500 Internal Server Error responses generated via exception handler preserve CORS headers."""
        # Querying an endpoint that triggers an exception or passing a route raising exception
        # We can dynamically register a temporary test route on app
        from fastapi import APIRouter
        temp_router = APIRouter()

        @temp_router.get("/api/test-trigger-500-internal")
        def _trigger_500():
            raise RuntimeError("Synthetic test 500 error for CORS verification")

        app.include_router(temp_router)

        try:
            res = self.client.get("/api/test-trigger-500-internal", headers={"Origin": PROD_ORIGIN})
            self.assertEqual(res.status_code, 500)
            self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
            self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")
        finally:
            # Clean up temporary router from app
            app.router.routes = [r for r in app.router.routes if getattr(r, "path", None) != "/api/test-trigger-500-internal"]

    def test_08_options_preflight_auth_me(self):
        """Verify OPTIONS preflight on /api/auth/me succeeds with 200, credentials, and allow-headers."""
        res = self.client.options(
            "/api/auth/me",
            headers={
                "Origin": PROD_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "authorization, content-type",
            }
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
        self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")
        allowed_headers = res.headers.get("access-control-allow-headers", "").lower()
        self.assertIn("authorization", allowed_headers)
        self.assertIn("content-type", allowed_headers)
        self.assertIn("GET", res.headers.get("access-control-allow-methods", ""))

    def test_09_options_preflight_auth_me_variations(self):
        """Verify OPTIONS preflight on /api/auth/me with various header permutations and casing."""
        for req_headers in [
            "content-type",
            "authorization",
            "Authorization, Content-Type",
            "content-type, authorization",
        ]:
            res = self.client.options(
                "/api/auth/me",
                headers={
                    "Origin": PROD_ORIGIN,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": req_headers,
                }
            )
            self.assertEqual(res.status_code, 200)
            self.assertEqual(res.headers.get("access-control-allow-origin"), PROD_ORIGIN)
            self.assertEqual(res.headers.get("access-control-allow-credentials"), "true")


if __name__ == "__main__":
    unittest.main()
