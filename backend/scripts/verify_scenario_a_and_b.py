"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Script: scripts/verify_scenario_a_and_b.py

Comprehensive Automated Verification Suite for:
Scenario A — Local Development (Frontend, backend, sensor on same machine)
Scenario B — Hosted Deployment (Remote hosting server, separate client Windows sensor)
Security & Cross-User Isolation Audit
"""

import os
import sys
import time
import uuid
from pathlib import Path
from starlette.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from src.api.main import app
from src.database.database import SessionLocal
from src.database.repository import SensorEnrollmentRepository, UserRepository


def run_audit():
    print("=" * 80)
    print("  NETRA AUDIT: SCENARIO A & SCENARIO B SENSOR & HOSTING VERIFICATION")
    print("=" * 80)

    # --------------------------------------------------------------------------
    # SCENARIO A: Local Development (Same Machine)
    # --------------------------------------------------------------------------
    print("\n[SCENARIO A] Testing Local Development Mode (127.0.0.1)...")
    local_client = TestClient(app, client=("127.0.0.1", 54321))

    # 1. Register/Login local operator
    local_email = f"local_dev_{uuid.uuid4().hex[:6]}@soc.gov.in"
    reg_resp = local_client.post(
        "/api/auth/register",
        json={"full_name": "Local Dev User", "email": local_email, "password": "StrongPassword123!"}
    )
    assert reg_resp.status_code == 201, f"Local register failed: {reg_resp.text}"

    login_resp = local_client.post(
        "/api/auth/login",
        json={"email": local_email, "password": "StrongPassword123!"}
    )
    assert login_resp.status_code == 200, f"Local login failed: {login_resp.text}"

    # 2. Query capture status from localhost
    status_resp = local_client.get("/api/capture/status")
    assert status_resp.status_code == 200, f"Local status failed: {status_resp.text}"
    status_data = status_resp.json()
    assert status_data.get("is_local_client") is True, "Localhost must be identified as local client"
    print("  ✓ Localhost correctly identified: is_local_client == True")

    # 3. Test capture start/stop on local machine
    start_resp = local_client.post("/api/capture/start", json={"interface": None})
    assert start_resp.status_code == 200, f"Local capture start failed: {start_resp.text}"
    print(f"  ✓ Local capture started successfully: {start_resp.json().get('message')}")

    time.sleep(1.0)
    stop_resp = local_client.post("/api/capture/stop", json={})
    assert stop_resp.status_code == 200, f"Local capture stop failed: {stop_resp.text}"
    print(f"  ✓ Local capture stopped cleanly: {stop_resp.json().get('message')}")
    print("[SCENARIO A] PASS: Local development capture workflow is fully functional.")

    # --------------------------------------------------------------------------
    # SCENARIO B: Hosted Deployment (Remote Server, Separate Windows Client)
    # --------------------------------------------------------------------------
    print("\n[SCENARIO B] Testing Hosted Remote Deployment Mode...")
    remote_ip = "203.0.113.45"  # Simulated external non-local IP
    remote_client = TestClient(app, client=(remote_ip, 49822))

    # 1. Register User Alice (Workstation 1)
    alice_email = f"alice_{uuid.uuid4().hex[:6]}@corp.internal"
    reg_a = remote_client.post(
        "/api/auth/register",
        json={"full_name": "Alice Workstation", "email": alice_email, "password": "StrongPassword123!"}
    )
    assert reg_a.status_code == 201, f"Alice register failed: {reg_a.text}"

    login_a = remote_client.post(
        "/api/auth/login",
        json={"email": alice_email, "password": "StrongPassword123!"}
    )
    assert login_a.status_code == 200, f"Alice login failed: {login_a.text}"

    # 2. Verify that Remote Browser is identified as remote and direct server NIC capture is blocked
    remote_status = remote_client.get("/api/capture/status")
    assert remote_status.status_code == 200
    assert remote_status.json().get("is_local_client") is False, "Remote client must have is_local_client == False"
    print(f"  ✓ Remote client ({remote_ip}) identified as remote: is_local_client == False")

    direct_capture_resp = remote_client.post("/api/capture/start", json={"interface": "eth0"})
    assert direct_capture_resp.status_code == 403, "Remote client must NOT be allowed direct server NIC capture"
    print("  ✓ Remote browser direct server NIC capture blocked with HTTP 403 (verify_local_access enforced)")

    # 3. Alice enrolls her Windows sensor on her remote laptop
    sensor_slug = f"sensor-alice-{uuid.uuid4().hex[:6]}"
    enroll_resp = remote_client.post(
        "/api/sensor/enroll",
        json={"sensor_id": sensor_slug, "name": "Alice Windows 11 Laptop"}
    )
    assert enroll_resp.status_code == 200, f"Enrollment failed: {enroll_resp.text}"
    enroll_data = enroll_resp.json()
    api_key = enroll_data.get("api_key")
    assert api_key and api_key.startswith("netra_live_"), "Valid API key must be returned upon enrollment"
    print(f"  ✓ Sensor '{sensor_slug}' enrolled. Cryptographic key issued to user.")

    # 4. Agent communicates via outbound HTTPS telemetry to /api/sensor/ingest
    # Client sends an initial heartbeat record
    agent_client = TestClient(app, client=(remote_ip, 49830))
    hb_payload = {
        "sensor_id": sensor_slug,
        "batch_id": f"batch_{int(time.time()*1000)}_01",
        "sent_at": time.time(),
        "actual_state": "STOPPED",
        "records": [
            {
                "record_id": f"hb_rec_{uuid.uuid4().hex[:8]}",
                "sensor_id": sensor_slug,
                "sensor_version": "1.0.0-win",
                "hostname": "ALICE-WIN11-PC",
                "timestamp": time.time(),
                "record_type": "HEARTBEAT",
                "interface": "Wi-Fi 3"
            }
        ]
    }
    ingest_resp = agent_client.post(
        "/api/sensor/ingest",
        json=hb_payload,
        headers={"X-Sensor-Key": api_key}
    )
    assert ingest_resp.status_code == 200, f"Ingest failed: {ingest_resp.text}"
    ingest_data = ingest_resp.json()
    assert ingest_data.get("command") == "STOPPED", "Default target command should be STOPPED"
    print("  ✓ Agent heartbeat ingested successfully over simulated outbound HTTPS.")

    # 5. Dashboard issues START command to Alice's sensor
    control_start = remote_client.post(
        f"/api/sensor/{sensor_slug}/control",
        json={"command": "START", "interface": "Wi-Fi 3"}
    )
    assert control_start.status_code == 200, f"Control START failed: {control_start.text}"
    assert control_start.json().get("target_state") == "RUNNING"
    print("  ✓ Alice's browser issued START command to her enrolled remote sensor.")

    # 6. Agent polls/sends next batch and receives the START command
    agent_batch_2 = {
        "sensor_id": sensor_slug,
        "batch_id": f"batch_{int(time.time()*1000)}_02",
        "sent_at": time.time(),
        "actual_state": "STARTING",
        "records": [
            {
                "record_id": f"rec_{uuid.uuid4().hex[:8]}",
                "sensor_id": sensor_slug,
                "sensor_version": "1.0.0-win",
                "hostname": "ALICE-WIN11-PC",
                "timestamp": time.time(),
                "record_type": "HEARTBEAT",
                "interface": "Wi-Fi 3"
            }
        ]
    }
    ingest_resp_2 = agent_client.post(
        "/api/sensor/ingest",
        json=agent_batch_2,
        headers={"X-Sensor-Key": api_key}
    )
    assert ingest_resp_2.status_code == 200
    assert ingest_resp_2.json().get("command") == "RUNNING", "Agent must receive 'RUNNING' command in response"
    print("  ✓ Agent received START ('RUNNING') command dispatched from backend.")

    # 7. Agent starts sniffing and confirms actual_state == "RUNNING" with captured flow metadata
    flow_id_1 = f"flow_alice_{uuid.uuid4().hex[:8]}"
    agent_flow_batch = {
        "sensor_id": sensor_slug,
        "batch_id": f"batch_{int(time.time()*1000)}_03",
        "sent_at": time.time(),
        "actual_state": "RUNNING",
        "records": [
            {
                "record_id": f"rec_{uuid.uuid4().hex[:8]}",
                "sensor_id": sensor_slug,
                "sensor_version": "1.0.0-win",
                "hostname": "ALICE-WIN11-PC",
                "timestamp": time.time(),
                "record_type": "FLOW",
                "interface": "Wi-Fi 3",
                "flow": {
                    "flow_id": flow_id_1,
                    "src_ip": "192.168.1.105",
                    "dst_ip": "93.184.216.34",
                    "src_port": 54321,
                    "dst_port": 443,
                    "protocol": "TCP",
                    "duration": 2.5,
                    "total_packets": 14,
                    "total_bytes": 1420
                }
            }
        ]
    }
    ingest_resp_3 = agent_client.post(
        "/api/sensor/ingest",
        json=agent_flow_batch,
        headers={"X-Sensor-Key": api_key}
    )
    assert ingest_resp_3.status_code == 200
    print("  ✓ Agent confirmed actual_state == 'RUNNING' and transmitted captured flow telemetry.")

    # 8. Verify Dashboard status confirmation
    alice_sensors = remote_client.get("/api/sensor/list").json()
    alice_sensor_data = next(s for s in alice_sensors if s["sensor_id"] == sensor_slug)
    assert alice_sensor_data.get("actual_state") == "RUNNING"
    assert alice_sensor_data.get("target_state") == "RUNNING"
    assert alice_sensor_data.get("flows_uploaded") >= 1
    print("  ✓ Dashboard query confirms sensor is active with actual_state == 'RUNNING'.")

    # 9. Dashboard issues STOP command
    control_stop = remote_client.post(
        f"/api/sensor/{sensor_slug}/control",
        json={"command": "STOP"}
    )
    assert control_stop.status_code == 200
    assert control_stop.json().get("target_state") == "STOPPED"
    print("  ✓ Dashboard successfully queued STOP command.")

    # --------------------------------------------------------------------------
    # SECURITY & ISOLATION AUDIT
    # --------------------------------------------------------------------------
    print("\n[SECURITY AUDIT] Testing Cross-User Isolation and Credential Enforcement...")

    # A. Register User Bob (Attacker / Different User)
    bob_client = TestClient(app, client=("198.51.100.22", 60100))
    bob_email = f"bob_{uuid.uuid4().hex[:6]}@other.org"
    bob_client.post(
        "/api/auth/register",
        json={"full_name": "Bob Separate User", "email": bob_email, "password": "StrongPassword123!"}
    )
    bob_client.post("/api/auth/login", json={"email": bob_email, "password": "StrongPassword123!"})

    # B. Bob attempts to control Alice's sensor -> Must be 403 Forbidden
    bob_control = bob_client.post(
        f"/api/sensor/{sensor_slug}/control",
        json={"command": "STOP"}
    )
    assert bob_control.status_code == 403, f"Expected 403 Forbidden for cross-user control, got {bob_control.status_code}"
    print("  ✓ User B (Bob) CANNOT control User A (Alice's) sensor: HTTP 403 Forbidden enforced.")

    # C. Bob attempts to revoke Alice's sensor -> Must be 403 Forbidden
    bob_revoke = bob_client.post(
        "/api/sensor/revoke",
        json={"sensor_id": sensor_slug}
    )
    assert bob_revoke.status_code == 403, f"Expected 403 Forbidden for cross-user revoke, got {bob_revoke.status_code}"
    print("  ✓ User B CANNOT revoke User A's sensor: HTTP 403 Forbidden enforced.")

    # D. Bob queries sensor list -> Alice's sensor must NOT appear
    bob_sensors = bob_client.get("/api/sensor/list").json()
    assert not any(s["sensor_id"] == sensor_slug for s in bob_sensors), "Alice's sensor must not appear in Bob's sensor list"
    print("  ✓ User B CANNOT see User A's enrolled sensor in sensor list.")

    # E. Bob queries flows -> Alice's sensor flow must NOT be accessible
    bob_flow_detail = bob_client.get(f"/api/flows/{flow_id_1}")
    assert bob_flow_detail.status_code == 404, "Alice's flow must not be accessible to Bob"
    print("  ✓ User B CANNOT read User A's ingested network flows.")

    # F. Invalid credentials rejection
    invalid_key_resp = agent_client.post(
        "/api/sensor/ingest",
        json=hb_payload,
        headers={"X-Sensor-Key": "netra_live_invalid_bad_key_123456789"}
    )
    assert invalid_key_resp.status_code == 401, f"Expected 401 for invalid key, got {invalid_key_resp.status_code}"
    print("  ✓ Invalid sensor API keys are rejected with HTTP 401 Unauthorized.")

    # G. Revoked credentials rejection
    alice_revoke = remote_client.post("/api/sensor/revoke", json={"sensor_id": sensor_slug})
    assert alice_revoke.status_code == 200
    revoked_ingest_resp = agent_client.post(
        "/api/sensor/ingest",
        json=hb_payload,
        headers={"X-Sensor-Key": api_key}
    )
    assert revoked_ingest_resp.status_code in (401, 403), f"Expected 401 or 403 for revoked key, got {revoked_ingest_resp.status_code}"
    print(f"  ✓ Revoked sensor API keys are immediately rejected (HTTP {revoked_ingest_resp.status_code}).")

    # H. Zero payload enforcement: forbidden payload keys rejection
    payload_injection_test = {
        "sensor_id": sensor_slug,
        "batch_id": f"batch_{int(time.time()*1000)}_bad",
        "sent_at": time.time(),
        "records": [
            {
                "record_id": f"bad_rec_{uuid.uuid4().hex[:6]}",
                "record_type": "FLOW",
                "raw_packet": "4500003c1a2b40004006c5...",
                "payload_hex": "deadbeef"
            }
        ]
    }
    # Create temporary sensor for zero-payload test
    tmp_sensor = f"sensor-tmp-{uuid.uuid4().hex[:6]}"
    tmp_enroll = remote_client.post("/api/sensor/enroll", json={"sensor_id": tmp_sensor, "name": "Temp Test"}).json()
    tmp_key = tmp_enroll.get("api_key")
    payload_injection_test["sensor_id"] = tmp_sensor
    bad_payload_resp = agent_client.post(
        "/api/sensor/ingest",
        json=payload_injection_test,
        headers={"X-Sensor-Key": tmp_key}
    )
    # Batch rejected or errors recorded
    assert bad_payload_resp.status_code == 200
    assert bad_payload_resp.json().get("rejected") == 1
    print("  ✓ Prohibited packet payload keys ('raw_packet', 'payload_hex') rejected by zero-payload validator.")

    # 8. Test Windows Sensor Package Download and Owner Verification
    import io
    import json
    import zipfile
    alice_download = remote_client.get(f"/api/sensor/download/windows-agent?sensor_id={sensor_slug}&api_key={api_key}")
    assert alice_download.status_code == 200
    assert alice_download.headers.get("content-type") == "application/zip"
    assert "attachment" in alice_download.headers.get("content-disposition", "")
    zip_buf = io.BytesIO(alice_download.content)
    with zipfile.ZipFile(zip_buf, "r") as zf:
        namelist = zf.namelist()
        assert any("start_sensor.bat" in name for name in namelist), "start_sensor.bat not found in zip"
        assert any("launch_elevated.ps1" in name for name in namelist), "launch_elevated.ps1 not found in zip"
        assert any("sensor_config.json" in name for name in namelist), "sensor_config.json not found in zip"
        assert any("README.txt" in name for name in namelist), "README.txt not found in zip"
        assert any("windows_sensor.py" in name for name in namelist), "windows_sensor.py not found in zip"
        config_entry = [n for n in namelist if n.endswith("sensor_config.json")][0]
        cfg = json.loads(zf.read(config_entry).decode("utf-8"))
        assert cfg["sensor_id"] == sensor_slug
        assert cfg["api_key"] == api_key
    print("  ✓ Standalone Windows sensor package generated dynamically with pre-configured credentials.")

    # Cross-user download denial: Bob cannot download Alice's sensor package
    bob_download = bob_client.get(f"/api/sensor/download/windows-agent?sensor_id={sensor_slug}")
    assert bob_download.status_code == 403
    print("  ✓ User B cannot download User A's sensor package (HTTP 403 Forbidden).")

    # 9. Test Reverse Proxy & Hosted Mode Server NIC Protection
    # Case: Client on localhost socket but X-Forwarded-For indicates external client
    proxy_spoof_client = TestClient(app, cookies=remote_client.cookies)
    proxy_resp = proxy_spoof_client.post(
        "/api/capture/start",
        json={"interface": "Wi-Fi 3"},
        headers={"X-Forwarded-For": "203.0.113.88"}
    )
    assert proxy_resp.status_code == 403
    print("  ✓ Reverse-proxy requests with external X-Forwarded-For cannot trigger server capture (HTTP 403).")

    # Case: Server hosted mode flag (NETRA_HOSTED=true) blocks direct server capture completely
    os.environ["NETRA_HOSTED"] = "true"
    try:
        hosted_local_client = TestClient(app, cookies=remote_client.cookies)
        hosted_resp = hosted_local_client.post(
            "/api/capture/start",
            json={"interface": "Wi-Fi 3"}
        )
        assert hosted_resp.status_code == 403
        print("  ✓ Hosted mode flag (NETRA_HOSTED=true) unconditionally disables direct server capture.")
    finally:
        os.environ.pop("NETRA_HOSTED", None)

    print("\n" + "=" * 80)
    print("  ALL SCENARIOS AND SECURITY AUDIT CHECKS PASSED SUCCESSFULLY (100% PASS)")
    print("=" * 80)


if __name__ == "__main__":
    run_audit()
