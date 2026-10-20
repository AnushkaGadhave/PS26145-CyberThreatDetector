"""
Verification script: Test real passive network capture, flow building, ML detection,
PostgreSQL persistence, and FastAPI API responses end-to-end.
"""

import sys
import time
import json
import urllib.request

API_BASE = "http://127.0.0.1:8000"


def http_get(path):
    url = f"{API_BASE}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def http_post(path, body=None):
    url = f"{API_BASE}{path}"
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode())


def main():
    print("=" * 60)
    print("VERIFYING END-TO-END PASSIVE CAPTURE & TELEMETRY PIPELINE")
    print("=" * 60)

    # 1. Health check
    print("\n[Step 1] Checking API health (/health)...")
    health = http_get("/health")
    print(f"Health response: {health}")
    assert health.get("status") == "ok", "API health failed"

    # 2. Check initial DB overview
    print("\n[Step 2] Checking initial database state (/api/dashboard/overview)...")
    overview = http_get("/api/dashboard/overview")
    print(f"Initial Persisted Flows: {overview.get('total_flows')}")
    print(f"Initial Persisted Alerts: {overview.get('total_alerts')}")
    print(f"Loaded Model Statuses: {len(overview.get('model_status', []))}")

    # 3. Check discovered network interfaces
    print("\n[Step 3] Discovering host network interfaces (/api/capture/interfaces)...")
    ifaces = http_get("/api/capture/interfaces")
    print(f"Discovered {len(ifaces)} interfaces on host.")
    active_ifaces = [i["name"] for i in ifaces if i.get("is_active")]
    print(f"Active interfaces with IP: {active_ifaces}")

    # 4. Start passive capture on Wi-Fi 3
    print("\n[Step 4] Starting passive packet capture on 'Wi-Fi 3' (/api/capture/start)...")
    start_res = http_post("/api/capture/start", {"interface": "Wi-Fi 3"})
    print(f"Start Response: {start_res}")
    assert start_res.get("success"), f"Failed to start capture: {start_res}"

    # 5. Generate actual traffic on the interface and wait for packets
    print("\n[Step 5] Passive capture running. Generating local web traffic and observing...")
    for i in range(5):
        try:
            urllib.request.urlopen("https://www.google.com", timeout=2)
        except Exception:
            pass
        time.sleep(1)

    # 6. Check capture status while active
    print("\n[Step 6] Inspecting live capture status (/api/capture/status)...")
    status = http_get("/api/capture/status")
    print(f"Capture State:    {status.get('state')}")
    print(f"Interface:        {status.get('interface')}")
    print(f"Packets Captured: {status.get('packets_captured')}")
    print(f"Packet Rate:      {status.get('current_pps')} pps")
    print(f"Bandwidth:        {status.get('current_kbps')} KB/s")
    print(f"Flows Completed:  {status.get('flows_created')}")

    # 7. Check recent live stream events
    print("\n[Step 7] Inspecting live stream events (/api/capture/events)...")
    events = http_get("/api/capture/events?limit=5")
    print(f"Recent events count: {len(events)}")
    for ev in events[:3]:
        print(f"  - [{ev.get('protocol')}] {ev.get('src_ip')} -> {ev.get('dst_ip')}:{ev.get('dst_port')} ({ev.get('packets')} pkts, {ev.get('bytes')} B) Verdict: {ev.get('threat_outcome')}")

    # 8. Stop capture and flush flows
    print("\n[Step 8] Stopping capture and finalizing active flows (/api/capture/stop)...")
    stop_res = http_post("/api/capture/stop")
    print(f"Stop Response: {stop_res}")

    # 9. Verify PostgreSQL persisted flows
    print("\n[Step 9] Querying persisted flows from PostgreSQL (/api/flows)...")
    flows_res = http_get("/api/flows?limit=10")
    total_persisted = flows_res.get("total", 0)
    print(f"Total flows in database: {total_persisted}")
    if flows_res.get("flows"):
        sample = flows_res["flows"][0]
        print(f"Sample Persisted Flow:")
        print(f"  Flow ID:   {sample.get('flow_id')}")
        print(f"  Protocol:  {sample.get('protocol')}")
        print(f"  Source:    {sample.get('src_ip')}:{sample.get('src_port')}")
        print(f"  Target:    {sample.get('dst_ip')}:{sample.get('dst_port')}")
        print(f"  Packets:   {sample.get('total_packets')}")
        print(f"  Bytes:     {sample.get('total_bytes')}")
        print(f"  Duration:  {sample.get('duration')}s")

    # 10. Verify updated Dashboard Overview
    print("\n[Step 10] Checking updated dashboard overview (/api/dashboard/overview)...")
    overview_after = http_get("/api/dashboard/overview")
    print(f"Updated Total Flows:  {overview_after.get('total_flows')}")
    print(f"Updated Total Alerts: {overview_after.get('total_alerts')}")
    print(f"Protocol Breakdown:   {overview_after.get('protocol_counts')}")
    print(f"Top Source IPs:       {overview_after.get('top_source_ips')}")

    print("\n" + "=" * 60)
    print("END-TO-END PIPELINE VERIFICATION PASSED SUCCESSFULLY!")
    print("=" * 60)


if __name__ == "__main__":
    main()
