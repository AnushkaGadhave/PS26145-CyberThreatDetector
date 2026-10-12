"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Script: scripts.verify_api_live

Validation script testing live PostgreSQL database integration and all FastAPI endpoints.
"""

import sys
import json
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient
from src.api.main import app


def run_live_verification():
    print("=========================================")
    print("LIVE API ENDPOINT VERIFICATION")
    print("=========================================\n")

    client = TestClient(app)

    # 1. GET /health
    res = client.get("/health")
    print(f"1. GET /health -> Status: {res.status_code}")
    print(f"   Response: {json.dumps(res.json(), indent=2)}\n")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # 2. GET /api/flows
    res = client.get("/api/flows?limit=3")
    print(f"2. GET /api/flows?limit=3 -> Status: {res.status_code}")
    flow_data = res.json()
    print(f"   Total Flows: {flow_data['total']}, Returned: {len(flow_data['flows'])}")
    if flow_data["flows"]:
        print(f"   Sample Flow ID: {flow_data['flows'][0]['flow_id']}, Protocol: {flow_data['flows'][0]['protocol']}, Context: {flow_data['flows'][0]['traffic_context']}")
    print()
    assert res.status_code == 200

    # 3. GET /api/flows/{flow_id}
    if flow_data["flows"]:
        sample_fid = flow_data["flows"][0]["flow_id"]
        res = client.get(f"/api/flows/{sample_fid}")
        print(f"3. GET /api/flows/{sample_fid} -> Status: {res.status_code}")
        print(f"   Flow src: {res.json()['src_ip']}:{res.json()['src_port']} -> dst: {res.json()['dst_ip']}:{res.json()['dst_port']}\n")
        assert res.status_code == 200

    # 4. GET /api/alerts
    res = client.get("/api/alerts?limit=3")
    print(f"4. GET /api/alerts?limit=3 -> Status: {res.status_code}")
    alert_data = res.json()
    print(f"   Total Alerts: {alert_data['total']}, Returned: {len(alert_data['alerts'])}")
    if alert_data["alerts"]:
        print(f"   Sample Alert ID: {alert_data['alerts'][0]['alert_id']}, Threat: {alert_data['alerts'][0]['threat_class']}, Severity: {alert_data['alerts'][0]['severity']}")
    print()
    assert res.status_code == 200

    # 5. GET /api/alerts/{alert_id}
    if alert_data["alerts"]:
        sample_aid = alert_data["alerts"][0]["alert_id"]
        res = client.get(f"/api/alerts/{sample_aid}")
        print(f"5. GET /api/alerts/{sample_aid} -> Status: {res.status_code}")
        alert_detail = res.json()
        print(f"   Evidence Summary: {alert_detail['evidence_summary']}")
        print(f"   Model Status: {alert_detail['model_status']}")
        print(f"   Traffic Context: {alert_detail['traffic_context']}\n")
        assert res.status_code == 200

    # 6. GET /api/alerts/recent
    res = client.get("/api/alerts/recent?limit=5")
    print(f"6. GET /api/alerts/recent?limit=5 -> Status: {res.status_code}")
    print(f"   Returned recent alerts: {len(res.json())}\n")
    assert res.status_code == 200

    # 7. GET /api/alerts/summary
    res = client.get("/api/alerts/summary")
    print(f"7. GET /api/alerts/summary -> Status: {res.status_code}")
    print(f"   Summary: {json.dumps(res.json(), indent=2)}\n")
    assert res.status_code == 200

    # 8. GET /api/models/status
    res = client.get("/api/models/status")
    print(f"8. GET /api/models/status -> Status: {res.status_code}")
    print(f"   Model Statuses: {json.dumps(res.json(), indent=2)}\n")
    assert res.status_code == 200
    assert len(res.json()) == 3

    # 9. GET /api/dashboard/overview
    res = client.get("/api/dashboard/overview")
    print(f"9. GET /api/dashboard/overview -> Status: {res.status_code}")
    print(f"   Dashboard Overview: {json.dumps(res.json(), indent=2)}\n")
    assert res.status_code == 200

    # 10. GET /docs and /openapi.json
    res_docs = client.get("/docs")
    res_openapi = client.get("/openapi.json")
    print(f"10. GET /docs -> Status: {res_docs.status_code}, GET /openapi.json -> Status: {res_openapi.status_code}\n")
    assert res_docs.status_code == 200
    assert res_openapi.status_code == 200

    print("=========================================")
    print("ALL 10 API ENDPOINTS VERIFIED SUCCESSFULLY")
    print("=========================================")


if __name__ == "__main__":
    run_live_verification()
