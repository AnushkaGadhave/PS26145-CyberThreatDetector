"""
End-to-End Verification Script: Per-User Local Packet Capture & Cross-User Data Isolation
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
"""

import sys
import time
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from fastapi.testclient import TestClient
from src.api.main import app
from src.database.database import SessionLocal
from src.database.repository import UserRepository, FlowRepository, AlertRepository
from src.capture.capture_service import capture_manager


def run_verification():
    print("========================================================================")
    print("   NETRA Verification: Per-User Local Capture & Isolation")
    print("========================================================================")

    # 1. Create separate test clients for User A, User B, and Remote Device
    client_a = TestClient(app, client=("127.0.0.1", 51001))
    client_b = TestClient(app, client=("127.0.0.1", 51002))
    client_remote = TestClient(app, client=("192.168.1.150", 51003))

    ts = int(time.time())
    email_a = f"alice_{ts}@defense.local"
    email_b = f"bob_{ts}@defense.local"
    password = "LiveMonitorSecret2026!"

    print(f"\n[Test 1] Registering User A ({email_a}) and User B ({email_b})...")
    res_reg_a = client_a.post("/api/auth/register", json={
        "full_name": "Alice Operator",
        "email": email_a,
        "password": password
    })
    assert res_reg_a.status_code == 201, f"User A registration failed: {res_reg_a.text}"
    user_a_id = res_reg_a.json()["user"]["user_id"]
    print(f"  [+] User A registered: ID={user_a_id}")

    res_reg_b = client_b.post("/api/auth/register", json={
        "full_name": "Bob Analyst",
        "email": email_b,
        "password": password
    })
    assert res_reg_b.status_code == 201, f"User B registration failed: {res_reg_b.text}"
    user_b_id = res_reg_b.json()["user"]["user_id"]
    print(f"  [+] User B registered: ID={user_b_id}")

    # 2. Remote Client restriction check
    print("\n[Test 2] Verifying remote client cannot start capture on server host...")
    client_remote.post("/api/auth/login", json={"email": email_a, "password": password})
    res_remote = client_remote.post("/api/capture/start", json={})
    assert res_remote.status_code == 403, f"Remote client should be rejected with 403, got {res_remote.status_code}"
    print(f"  [+] Remote client correctly rejected: {res_remote.json()['detail']}")

    # 3. User A starts local capture on Wi-Fi 3
    print("\n[Test 3] User A starts passive packet capture on local interface...")
    res_start_a = client_a.post("/api/capture/start", json={"interface": "Wi-Fi 3"})
    assert res_start_a.status_code == 200, f"User A failed to start capture: {res_start_a.text}"
    print(f"  [+] User A capture started: {res_start_a.json()['message']}")

    # Verify User A's status
    status_a = client_a.get("/api/capture/status").json()
    assert status_a["status"] == "RUNNING", f"Expected RUNNING, got {status_a['status']}"
    assert status_a["is_owner"] is True, "User A should be recognized as session owner"
    assert status_a["busy_by_other_user"] is False
    print(f"  [+] User A status confirmed: RUNNING (is_owner={status_a['is_owner']})")

    # 4. User B checks status and attempts control while User A's capture is active
    print("\n[Test 4] Verifying User B isolation while User A is capturing...")
    status_b = client_b.get("/api/capture/status").json()
    assert status_b["status"] == "STANDBY", f"User B should see STANDBY, got {status_b['status']}"
    assert status_b["busy_by_other_user"] is True, "User B should see busy_by_other_user=True"
    assert status_b["is_owner"] is False, "User B should not be owner"
    assert status_b["total_packets"] == 0, f"User B must not see User A's packet counts, got {status_b['total_packets']}"
    print(f"  [+] User B sees isolated STANDBY status with busy_by_other_user=True and 0 packets.")

    # User B tries to start capture -> Expect 409 Conflict
    res_start_b = client_b.post("/api/capture/start", json={"interface": "Wi-Fi 3"})
    assert res_start_b.status_code == 409, f"User B start should return 409 Conflict, got {res_start_b.status_code}"
    print(f"  [+] User B start blocked with 409 Conflict: {res_start_b.json()['detail']}")

    # User B tries to stop User A's capture -> Expect 403 Forbidden
    res_stop_b = client_b.post("/api/capture/stop")
    assert res_stop_b.status_code == 403, f"User B stop should return 403 Forbidden, got {res_stop_b.status_code}"
    print(f"  [+] User B stop blocked with 403 Forbidden: {res_stop_b.json()['detail']}")

    # 5. Let capture run briefly to observe real traffic
    print("\n[Test 5] Capturing live packets on active network interface...")
    time.sleep(2.5)
    status_a_live = client_a.get("/api/capture/status").json()
    print(f"  [+] Live Telemetry: Packets={status_a_live['packets_captured']}, "
          f"PPS={status_a_live['current_pps']}, State={status_a_live['state']}, "
          f"Diagnostic={status_a_live['diagnostic_state']}")

    # 6. User A stops their own capture session
    print("\n[Test 6] User A stops their own capture session...")
    res_stop_a = client_a.post("/api/capture/stop")
    assert res_stop_a.status_code == 200, f"User A stop failed: {res_stop_a.text}"
    print(f"  [+] User A stopped capture: {res_stop_a.json()['message']}")

    # 7. Verify Data Scoping (Flows, Alerts, Events)
    print("\n[Test 7] Verifying User B cannot see User A's captured flows, alerts, or events...")
    flows_a = client_a.get("/api/flows").json()
    flows_b = client_b.get("/api/flows").json()
    alerts_a = client_a.get("/api/alerts").json()
    alerts_b = client_b.get("/api/alerts").json()
    events_a = client_a.get("/api/capture/events").json()
    events_b = client_b.get("/api/capture/events").json()

    print(f"  User A - Flows: {flows_a.get('total', 0)}, Alerts: {alerts_a.get('total', 0)}, Live Events: {len(events_a)}")
    print(f"  User B - Flows: {flows_b.get('total', 0)}, Alerts: {alerts_b.get('total', 0)}, Live Events: {len(events_b)}")
    assert flows_b.get("total", 0) == 0, f"User B should see 0 flows, got {flows_b.get('total')}"
    assert alerts_b.get("total", 0) == 0, f"User B should see 0 alerts, got {alerts_b.get('total')}"
    assert len(events_b) == 0, f"User B should see 0 live events, got {len(events_b)}"
    print("  [+] Strict cross-user data isolation verified: User B sees zero flows, alerts, and events.")

    # 8. User B can now start their own capture session
    print("\n[Test 8] User B starts their own capture session now that adapter is free...")
    res_start_b_ok = client_b.post("/api/capture/start", json={"interface": "Wi-Fi 3"})
    assert res_start_b_ok.status_code == 200, f"User B start should succeed, got {res_start_b_ok.text}"
    print(f"  [+] User B started their own capture: {res_start_b_ok.json()['message']}")

    status_b_now = client_b.get("/api/capture/status").json()
    assert status_b_now["is_owner"] is True, "User B should now be the session owner"
    print(f"  [+] User B verified as owner: is_owner={status_b_now['is_owner']}")

    # User B stops capture
    client_b.post("/api/capture/stop")
    print("  [+] User B stopped capture.")

    # 9. Verify Sensor Enrollment isolation
    print("\n[Test 9] Verifying Sensor Enrollment isolation...")
    res_en_a = client_a.post("/api/sensor/enroll", json={
        "sensor_id": f"sensor-alice-{ts}",
        "name": "Alice Laptop"
    })
    assert res_en_a.status_code == 200
    res_en_b = client_b.post("/api/sensor/enroll", json={
        "sensor_id": f"sensor-bob-{ts}",
        "name": "Bob Workstation"
    })
    assert res_en_b.status_code == 200

    list_a = client_a.get("/api/sensor/list").json()
    list_b = client_b.get("/api/sensor/list").json()

    sensor_ids_a = [s["sensor_id"] for s in list_a]
    sensor_ids_b = [s["sensor_id"] for s in list_b]

    assert f"sensor-alice-{ts}" in sensor_ids_a
    assert f"sensor-bob-{ts}" not in sensor_ids_a
    assert f"sensor-bob-{ts}" in sensor_ids_b
    assert f"sensor-alice-{ts}" not in sensor_ids_b
    print(f"  [+] User A sees only A's sensors ({sensor_ids_a})")
    print(f"  [+] User B sees only B's sensors ({sensor_ids_b})")

    # User B tries to revoke User A's sensor -> 403 Forbidden
    res_rev = client_b.post("/api/sensor/revoke", json={"sensor_id": f"sensor-alice-{ts}"})
    assert res_rev.status_code == 403, f"User B revoke of A's sensor should be 403, got {res_rev.status_code}"
    print(f"  [+] User B cannot revoke User A's sensor: {res_rev.json()['detail']}")

    print("\n========================================================================")
    print("   ALL VERIFICATION CHECKS PASSED PERFECTLY!")
    print("========================================================================")


if __name__ == "__main__":
    run_verification()
