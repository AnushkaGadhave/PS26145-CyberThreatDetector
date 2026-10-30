"""
Verification script for individual-user authentication, registration, session management,
and strict cross-user data isolation in NETRA.
"""

import os
import sys
import uuid
import requests

# Ensure backend directory is in python path
sys.path.insert(0, os.path.abspath("backend"))
sys.path.insert(0, os.path.abspath("."))

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("=" * 80)
    print("NETRA: INDIVIDUAL USER AUTHENTICATION & CROSS-USER ISOLATION VERIFICATION")
    print("=" * 80)

    # 1. Registration input validation
    print("\n--- 1. Testing Registration Validation ---")

    # Short password (<8 characters rejected by schema validation)
    res = requests.post(f"{BASE_URL}/api/auth/register", json={
        "full_name": "Test User",
        "email": "test-invalid-pw@example.com",
        "password": "short"
    })
    assert res.status_code == 422, f"Expected 422 for short password, got {res.status_code}: {res.text}"
    print("[PASS] Short password (<8 chars) rejected with 422 Unprocessable Entity")

    # Weak password (8+ characters but no digits rejected by policy)
    res = requests.post(f"{BASE_URL}/api/auth/register", json={
        "full_name": "Test User",
        "email": "test-no-digit@example.com",
        "password": "allcharacterswithoutdigit"
    })
    assert res.status_code == 400, f"Expected 400 for password without digits, got {res.status_code}: {res.text}"
    print("[PASS] Password without digits rejected with 400 Bad Request")

    # Invalid email
    res = requests.post(f"{BASE_URL}/api/auth/register", json={
        "full_name": "Test User",
        "email": "not-an-email",
        "password": "ValidPassword123!"
    })
    assert res.status_code == 422, f"Expected 422 for invalid email, got {res.status_code}"
    print("[PASS] Malformed email rejected with 422 Unprocessable Entity")

    # 2. User Registration (Alice & Bob)
    print("\n--- 2. Registering Two Distinct Accounts (Alice & Bob) ---")
    alice_email = f"alice_{uuid.uuid4().hex[:6]}@example.com"
    alice_password = "AliceSecurePass2026!"
    alice_name = "Alice Security"

    bob_email = f"bob_{uuid.uuid4().hex[:6]}@example.com"
    bob_password = "BobSecurePass2026!"
    bob_name = "Bob Defense"

    alice_session = requests.Session()
    alice_reg_res = alice_session.post(f"{BASE_URL}/api/auth/register", json={
        "full_name": alice_name,
        "email": alice_email,
        "password": alice_password
    })
    assert alice_reg_res.status_code == 201, f"Alice registration failed: {alice_reg_res.status_code} {alice_reg_res.text}"
    alice_data = alice_reg_res.json()["user"]
    alice_user_id = alice_data["user_id"]
    assert alice_data["email"] == alice_email
    assert alice_data["role"] in ("user", "analyst")
    assert "netra_session" in alice_session.cookies, "Alice did not receive session cookie"
    print(f"[PASS] User Alice registered successfully: {alice_email} (ID: {alice_user_id})")

    # Duplicate registration rejection
    dup_res = requests.post(f"{BASE_URL}/api/auth/register", json={
        "full_name": "Alice Duplicate",
        "email": alice_email,
        "password": "AnotherPassword123!"
    })
    assert dup_res.status_code == 409, f"Expected 409 for duplicate email, got {dup_res.status_code}"
    print(f"[PASS] Duplicate registration for {alice_email} correctly rejected with 409 Conflict")

    bob_session = requests.Session()
    bob_reg_res = bob_session.post(f"{BASE_URL}/api/auth/register", json={
        "full_name": bob_name,
        "email": bob_email,
        "password": bob_password
    })
    assert bob_reg_res.status_code == 201, f"Bob registration failed: {bob_reg_res.status_code} {bob_reg_res.text}"
    bob_data = bob_reg_res.json()["user"]
    bob_user_id = bob_data["user_id"]
    assert bob_data["email"] == bob_email
    assert bob_data["role"] in ("user", "analyst")
    assert "netra_session" in bob_session.cookies, "Bob did not receive session cookie"
    print(f"[PASS] User Bob registered successfully: {bob_email} (ID: {bob_user_id})")

    # 3. Session Restoration & Logout
    print("\n--- 3. Testing Session Restoration & Logout ---")
    alice_me_res = alice_session.get(f"{BASE_URL}/api/auth/me")
    assert alice_me_res.status_code == 200
    assert alice_me_res.json()["user"]["user_id"] == alice_user_id
    print(f"[PASS] Session restoration GET /api/auth/me confirmed for Alice")

    # Logout Alice and verify session termination
    logout_res = alice_session.post(f"{BASE_URL}/api/auth/logout")
    assert logout_res.status_code == 200
    me_after_logout = alice_session.get(f"{BASE_URL}/api/auth/me")
    assert me_after_logout.status_code == 401, f"Expected 401 after logout, got {me_after_logout.status_code}"
    print(f"[PASS] Logout cleared session and subsequent requests returned 401 Unauthorized")

    # Log Alice back in
    login_res = alice_session.post(f"{BASE_URL}/api/auth/login", json={
        "email": alice_email,
        "password": alice_password
    })
    assert login_res.status_code == 200
    assert "netra_session" in alice_session.cookies
    print(f"[PASS] Alice re-authenticated successfully via POST /api/auth/login")

    # 4. Sensor Enrollment Scoping
    print("\n--- 4. Testing Individual Sensor Enrollment & Scoping ---")
    alice_sensor_id = f"sensor-alice-{uuid.uuid4().hex[:6]}"
    bob_sensor_id = f"sensor-bob-{uuid.uuid4().hex[:6]}"

    # Alice enrolls her sensor
    alice_enroll_res = alice_session.post(f"{BASE_URL}/api/sensor/enroll", json={
        "sensor_id": alice_sensor_id,
        "name": "Alice Workstation Windows Sensor"
    })
    assert alice_enroll_res.status_code == 200, f"Alice enrollment failed: {alice_enroll_res.text}"
    alice_key = alice_enroll_res.json()["api_key"]
    print(f"[PASS] Alice enrolled sensor '{alice_sensor_id}'")

    # Bob enrolls his sensor
    bob_enroll_res = bob_session.post(f"{BASE_URL}/api/sensor/enroll", json={
        "sensor_id": bob_sensor_id,
        "name": "Bob Laptop Windows Sensor"
    })
    assert bob_enroll_res.status_code == 200, f"Bob enrollment failed: {bob_enroll_res.text}"
    bob_key = bob_enroll_res.json()["api_key"]
    print(f"[PASS] Bob enrolled sensor '{bob_sensor_id}'")

    # Alice lists sensors: should see ONLY her sensor
    alice_sensors = alice_session.get(f"{BASE_URL}/api/sensor/list").json()
    alice_sensor_ids = [s["sensor_id"] for s in alice_sensors]
    assert alice_sensor_id in alice_sensor_ids, "Alice cannot see her own sensor"
    assert bob_sensor_id not in alice_sensor_ids, "DATA LEAK: Alice can see Bob's sensor!"
    print(f"[PASS] Alice GET /api/sensor/list returns ONLY Alice's sensor: {alice_sensor_ids}")

    # Bob lists sensors: should see ONLY his sensor
    bob_sensors = bob_session.get(f"{BASE_URL}/api/sensor/list").json()
    bob_sensor_ids = [s["sensor_id"] for s in bob_sensors]
    assert bob_sensor_id in bob_sensor_ids, "Bob cannot see his own sensor"
    assert alice_sensor_id not in bob_sensor_ids, "DATA LEAK: Bob can see Alice's sensor!"
    print(f"[PASS] Bob GET /api/sensor/list returns ONLY Bob's sensor: {bob_sensor_ids}")

    # Bob tries to revoke Alice's sensor -> MUST BE FORBIDDEN (403)
    bob_revoke_alice = bob_session.post(f"{BASE_URL}/api/sensor/revoke", json={
        "sensor_id": alice_sensor_id
    })
    assert bob_revoke_alice.status_code == 403, f"Expected 403 Forbidden for cross-user revoke, got {bob_revoke_alice.status_code}"
    print(f"[PASS] Bob attempting to revoke Alice's sensor was blocked with 403 Forbidden")

    # 5. Ingestion and Flow / Alert / Dashboard Isolation
    print("\n--- 5. Testing Ingestion Scoping and Telemetry Isolation ---")
    flow_rec_id = f"flow-alice-{uuid.uuid4().hex[:8]}"
    ingest_payload = {
        "sensor_id": alice_sensor_id,
        "batch_id": f"batch-{uuid.uuid4().hex[:6]}",
        "sent_at": 1729440000.0,
        "records": [
            {
                "record_id": flow_rec_id,
                "record_type": "FLOW",
                "timestamp": 1729440000.0,
                "sensor_id": alice_sensor_id,
                "flow_id": f"192.168.1.50-10.0.0.1-443-49200-6-{uuid.uuid4().hex[:6]}",
                "src_ip": "192.168.1.50",
                "dst_ip": "10.0.0.1",
                "src_port": 49200,
                "dst_port": 443,
                "protocol": "TCP",
                "total_packets": 12,
                "total_bytes": 1540,
                "duration": 1.25,
                "forward_packets": 7,
                "backward_packets": 5,
                "forward_bytes": 840,
                "backward_bytes": 700,
                "packets_per_second": 9.6,
                "bytes_per_second": 1232.0,
                "syn_count": 1,
                "ack_count": 11,
                "fin_count": 0,
                "rst_count": 0,
                "psh_count": 2,
                "urg_count": 0,
                "iat_mean": 0.1,
                "iat_std": 0.05,
                "iat_min": 0.01,
                "iat_max": 0.25,
                "traffic_context": "UNLABELED_LIVE"
            }
        ]
    }

    # Ingest telemetry using Alice's sensor API key
    ingest_res = requests.post(
        f"{BASE_URL}/api/sensor/ingest",
        json=ingest_payload,
        headers={"X-Sensor-Key": alice_key}
    )
    assert ingest_res.status_code == 200, f"Ingestion failed: {ingest_res.status_code} {ingest_res.text}"
    assert ingest_res.json()["accepted"] == 1, f"Record not accepted: {ingest_res.json()}"
    print(f"[PASS] Telemetry batch ingested successfully for Alice's sensor")

    # Alice queries flows: should see her ingested flow
    alice_flows = alice_session.get(f"{BASE_URL}/api/flows?limit=10").json()
    assert alice_flows["total"] >= 1, "Alice should see her ingested flow"
    print(f"[PASS] Alice GET /api/flows returned {alice_flows['total']} flows")

    # Bob queries flows: MUST see 0 flows (cannot see Alice's flows)
    bob_flows = bob_session.get(f"{BASE_URL}/api/flows?limit=10").json()
    assert bob_flows["total"] == 0, f"DATA LEAK: Bob can see {bob_flows['total']} flows belonging to Alice!"
    print(f"[PASS] Bob GET /api/flows returned 0 flows (strict isolation confirmed)")

    # Bob queries dashboard overview: total_flows MUST be 0
    bob_overview = bob_session.get(f"{BASE_URL}/api/dashboard/overview").json()
    assert bob_overview["total_flows"] == 0, f"DATA LEAK: Bob overview reports {bob_overview['total_flows']} flows!"
    assert bob_overview["total_alerts"] == 0, f"DATA LEAK: Bob overview reports {bob_overview['total_alerts']} alerts!"
    print(f"[PASS] Bob GET /api/dashboard/overview returns 0 flows and 0 alerts")

    # Alice queries remote sensor events: sees her events
    alice_events = alice_session.get(f"{BASE_URL}/api/sensor/events").json()
    assert len(alice_events) >= 1, "Alice should see remote sensor events"
    print(f"[PASS] Alice GET /api/sensor/events returned {len(alice_events)} events")

    # Bob queries remote sensor events: returns 0 events
    bob_events = bob_session.get(f"{BASE_URL}/api/sensor/events").json()
    assert len(bob_events) == 0, f"DATA LEAK: Bob can see {len(bob_events)} remote sensor events!"
    print(f"[PASS] Bob GET /api/sensor/events returned 0 events (remote stream isolation confirmed)")

    # 6. Cleanup test records from database safely
    print("\n--- 6. Cleaning Up Test Accounts & Sensors ---")
    try:
        from src.database.database import SessionLocal
        from src.database.models import UserModel, UserSessionModel, SensorEnrollmentModel, FlowModel, SensorIngestRecordModel
        with SessionLocal() as db:
            db.query(SensorIngestRecordModel).filter(SensorIngestRecordModel.sensor_id.in_([alice_sensor_id, bob_sensor_id])).delete(synchronize_session=False)
            db.query(FlowModel).filter(FlowModel.sensor_id.in_([alice_sensor_id, bob_sensor_id])).delete(synchronize_session=False)
            db.query(SensorEnrollmentModel).filter(SensorEnrollmentModel.sensor_id.in_([alice_sensor_id, bob_sensor_id])).delete(synchronize_session=False)
            db.query(UserSessionModel).filter(UserSessionModel.user_id.in_([alice_user_id, bob_user_id])).delete(synchronize_session=False)
            db.query(UserModel).filter(UserModel.user_id.in_([alice_user_id, bob_user_id])).delete(synchronize_session=False)
            db.commit()
            print("[PASS] Test accounts and temporary sensors cleaned up safely")
    except Exception as clean_err:
        print(f"[WARN] Cleanup error: {clean_err}")

    print("\n" + "=" * 80)
    print("ALL TESTS PASSED: REGISTRATION, AUTHENTICATION, AND ISOLATION VERIFIED 100%")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
