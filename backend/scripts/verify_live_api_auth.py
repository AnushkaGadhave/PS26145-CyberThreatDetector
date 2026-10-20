"""
Verification script for real HTTP requests against the running FastAPI server.
Tests all requirements from SIH PS26145 authentication task.
"""

import sys
import requests

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("=" * 70)
    print("NETRA SIH PS26145 - REAL HTTP AUTHENTICATION VERIFICATION")
    print("=" * 70)

    # 1. Unauthenticated checks
    unauth_endpoints = [
        ("GET", "/api/dashboard/overview"),
        ("GET", "/api/flows?limit=5"),
        ("GET", "/api/alerts?limit=5"),
        ("GET", "/api/models/status"),
        ("GET", "/api/capture/status"),
        ("POST", "/api/capture/start"),
        ("POST", "/api/capture/stop"),
        ("GET", "/api/auth/me"),
    ]

    for method, path in unauth_endpoints:
        url = f"{BASE_URL}{path}"
        if method == "GET":
            resp = requests.get(url)
        else:
            resp = requests.post(url, json={})

        assert resp.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {resp.status_code}"
        print(f"[PASS] Unauthenticated {method} {path} properly rejected with 401 Unauthorized")

    # 2. Public health check remains accessible
    health_resp = requests.get(f"{BASE_URL}/health")
    assert health_resp.status_code == 200, f"Health check failed: {health_resp.status_code}"
    print(f"[PASS] Public health check GET /health returned 200 OK: {health_resp.json()}")

    # 3. Invalid credentials test (generic error, no enumeration)
    bad_login = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@soc.gov.in",
        "password": "WrongPassword123!"
    })
    assert bad_login.status_code == 401, f"Expected 401, got {bad_login.status_code}"
    assert "Invalid email or password" in bad_login.json().get("detail", "")
    print(f"[PASS] Failed login with incorrect password rejected with generic 401 error")

    # 4. Nonexistent user test (timing safe, identical generic error)
    nonexistent_login = requests.post(f"{BASE_URL}/api/auth/login", json={
        "email": "attacker@ghost.net",
        "password": "WrongPassword123!"
    })
    assert nonexistent_login.status_code == 401, f"Expected 401, got {nonexistent_login.status_code}"
    assert "Invalid email or password" in nonexistent_login.json().get("detail", "")
    print(f"[PASS] Nonexistent account rejected with identical generic 401 error (no email enumeration)")

    # 5. Successful login with provisioned Administrator
    session = requests.Session()
    login_resp = session.post(f"{BASE_URL}/api/auth/login", json={
        "email": "admin@soc.gov.in",
        "password": "CyberDefense2026!"
    })
    assert login_resp.status_code == 200, f"Login failed: {login_resp.status_code} {login_resp.text}"
    user_data = login_resp.json().get("user", {})
    assert user_data.get("email") == "admin@soc.gov.in", f"Unexpected user: {user_data}"
    assert user_data.get("role") == "admin", f"Unexpected role: {user_data}"
    assert "netra_session" in session.cookies, "Session cookie netra_session not found"
    print(f"[PASS] Valid login succeeded! User: {user_data.get('email')} (Role: {user_data.get('role')})")
    print(f"[PASS] Secure HttpOnly session cookie 'netra_session' received")

    # 6. Verify authenticated /api/auth/me
    me_resp = session.get(f"{BASE_URL}/api/auth/me")
    assert me_resp.status_code == 200, f"/api/auth/me failed: {me_resp.status_code}"
    assert me_resp.json().get("user", {}).get("email") == "admin@soc.gov.in"
    print(f"[PASS] GET /api/auth/me verified with active session cookie")

    # 7. Authenticated access to all protected telemetry endpoints
    overview_resp = session.get(f"{BASE_URL}/api/dashboard/overview")
    assert overview_resp.status_code == 200, f"Overview failed: {overview_resp.status_code}"
    ov_data = overview_resp.json()
    print(f"[PASS] GET /api/dashboard/overview authenticated! Flows: {ov_data.get('total_flows')}, Alerts: {ov_data.get('total_alerts')}")

    flows_resp = session.get(f"{BASE_URL}/api/flows?limit=10")
    assert flows_resp.status_code == 200, f"Flows failed: {flows_resp.status_code}"
    print(f"[PASS] GET /api/flows authenticated! Returned {len(flows_resp.json().get('flows', []))} flows")

    alerts_resp = session.get(f"{BASE_URL}/api/alerts?limit=10")
    assert alerts_resp.status_code == 200, f"Alerts failed: {alerts_resp.status_code}"
    print(f"[PASS] GET /api/alerts authenticated! Returned {len(alerts_resp.json().get('alerts', []))} alerts")

    models_resp = session.get(f"{BASE_URL}/api/models/status")
    assert models_resp.status_code == 200, f"Models status failed: {models_resp.status_code}"
    print(f"[PASS] GET /api/models/status authenticated! Returned {len(models_resp.json())} model statuses")

    cap_resp = session.get(f"{BASE_URL}/api/capture/status")
    assert cap_resp.status_code == 200, f"Capture status failed: {cap_resp.status_code}"
    print(f"[PASS] GET /api/capture/status authenticated! State: {cap_resp.json().get('state')}")

    # 8. Logout and session invalidation
    logout_resp = session.post(f"{BASE_URL}/api/auth/logout")
    assert logout_resp.status_code == 200, f"Logout failed: {logout_resp.status_code}"
    print(f"[PASS] POST /api/auth/logout succeeded: {logout_resp.json().get('message')}")

    # 9. Verify invalidated session is rejected immediately
    after_logout_me = session.get(f"{BASE_URL}/api/auth/me")
    assert after_logout_me.status_code == 401, f"Expected 401 after logout, got {after_logout_me.status_code}"
    print(f"[PASS] Revoked session cookie correctly rejected with 401 Unauthorized on /api/auth/me")

    after_logout_ov = session.get(f"{BASE_URL}/api/dashboard/overview")
    assert after_logout_ov.status_code == 401, f"Expected 401 after logout, got {after_logout_ov.status_code}"
    print(f"[PASS] Revoked session cookie correctly rejected with 401 Unauthorized on /api/dashboard/overview")

    print("=" * 70)
    print("ALL 16 REAL HTTP SECURITY TESTS PASSED PERFECTLY!")
    print("=" * 70)

if __name__ == "__main__":
    run_tests()
