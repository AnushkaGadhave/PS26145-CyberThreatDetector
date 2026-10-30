"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_sensor

FastAPI endpoints for:
1. Authenticated telemetry ingestion from remote NETRA Windows Sensors (POST /api/sensor/ingest).
2. Sensor device enrollment and cryptographic API key issuance (POST /api/sensor/enroll).
3. Enrolled sensor listing and status monitoring (GET /api/sensor/list).
4. Sensor credential revocation (POST /api/sensor/revoke).
5. Remote sensor live event streaming for the SOC dashboard (GET /api/sensor/events).

Security Guarantees:
- Strictly metadata-only (zero packet payloads accepted or stored).
- Cryptographic SHA-256 API key authentication.
- Bounded batch sizes (max 100 records) and request body limit (max 50 KB).
- Per-sensor sliding-window rate limiting.
- Idempotent processing with deduplication tracking.
"""

import io
import json
import time
import logging
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Request, Depends, HTTPException, Response, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import UserModel, SensorEnrollmentModel
from src.database.repository import (
    FlowRepository,
    AlertRepository,
    SensorEnrollmentRepository,
    SensorIngestRepository,
)
from src.auth.dependencies import get_current_user, require_admin
from src.auth.sensor_auth import (
    get_authenticated_sensor,
    generate_sensor_api_key,
    sensor_rate_limiter,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/sensor", tags=["Remote Sensor & Ingestion"])

# Maximum allowable request body size in bytes (50 KB)
MAX_INGEST_BODY_BYTES = 51200
# Maximum records allowed per ingestion batch
MAX_BATCH_RECORDS = 100

# Prohibited keys that indicate active payload inspection or packet payload storage
FORBIDDEN_PAYLOAD_KEYS = {
    "payload", "raw_packet", "packet_hex", "payload_hex", "raw_data", "packet_bytes"
}


class SensorEnrollRequest(BaseModel):
    sensor_id: str = Field(..., min_length=3, max_length=64, description="Unique sensor identifier (e.g. 'sensor-lab-win-01')")
    name: str = Field(..., min_length=2, max_length=100, description="Human-readable device/reviewer label")


class SensorRevokeRequest(BaseModel):
    sensor_id: str = Field(..., min_length=3, max_length=64, description="Sensor identifier to revoke")


class SensorBatchIngestRequest(BaseModel):
    sensor_id: str = Field(..., min_length=1, max_length=64, description="Identifier of the emitting sensor")
    batch_id: str = Field(..., min_length=1, max_length=128, description="Unique client-generated batch ID")
    sent_at: float = Field(..., description="Client epoch timestamp when batch was transmitted")
    records: List[Dict[str, Any]] = Field(..., description="Array of MetadataRecord dicts (max 100)")
    actual_state: Optional[str] = Field(None, description="Reported operational state: RUNNING, STOPPED, ERROR")


class SensorControlRequest(BaseModel):
    command: str = Field(..., pattern="^(START|STOP)$", description="Target command for remote sensor: START or STOP")
    interface: Optional[str] = Field(None, max_length=100, description="Target network adapter name for capture (optional)")


def _validate_zero_payload(record: Dict[str, Any], path: str = "record") -> None:
    """Recursively ensure no packet payload or raw binary data is present."""
    for k, v in record.items():
        if k.lower() in FORBIDDEN_PAYLOAD_KEYS:
            raise ValueError(f"Prohibited payload key '{k}' found at {path}. NETRA strictly enforces metadata-only ingestion.")
        if isinstance(v, dict):
            _validate_zero_payload(v, f"{path}.{k}")


@router.post(
    "/ingest",
    summary="Ingest Sensor Telemetry Batch",
    description=(
        "Authenticated endpoint for remote NETRA Windows Sensors to transmit flow and threat metadata batches. "
        "Enforces strict authentication via X-Sensor-Key, rate limiting, bounded batch sizes, deduplication, "
        "and zero-payload validation."
    )
)
async def ingest_sensor_batch(
    request: Request,
    body: SensorBatchIngestRequest,
    sensor: SensorEnrollmentModel = Depends(get_authenticated_sensor),
    db: Session = Depends(get_db)
):
    """
    Ingest a batch of metadata records from an authenticated remote sensor.
    Handles idempotency, database storage, and telemetry metrics.
    """
    # 1. Enforce payload size limit (max 50 KB)
    content_length = request.headers.get("Content-Length")
    if content_length and int(content_length) > MAX_INGEST_BODY_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Ingestion payload exceeds maximum allowed size of {MAX_INGEST_BODY_BYTES} bytes."
        )

    # 2. Enforce batch size limit
    if len(body.records) > MAX_BATCH_RECORDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size {len(body.records)} exceeds maximum limit of {MAX_BATCH_RECORDS} records."
        )

    # 3. Verify sensor_id in payload matches authenticated sensor
    if body.sensor_id != sensor.sensor_id:
        logger.warning(
            f"Sensor ID mismatch: payload specifies '{body.sensor_id}', "
            f"but credential belongs to '{sensor.sensor_id}'"
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sensor ID mismatch: request body does not match authenticated credential identity."
        )

    now = time.time()
    accepted_count = 0
    duplicate_count = 0
    rejected_count = 0
    ack_ids: List[str] = []
    errors: List[str] = []

    batch_packets = 0
    batch_flows = 0
    batch_alerts = 0
    latest_version = sensor.sensor_version
    latest_hostname = sensor.hostname

    client_ip = request.client.host if request.client else "unknown"

    # 4. Process each record in the batch
    for idx, rec in enumerate(body.records):
        if not isinstance(rec, dict):
            rejected_count += 1
            errors.append(f"Record at index {idx} is not a valid JSON object.")
            continue

        record_id = rec.get("record_id")
        if not record_id or not isinstance(record_id, str) or len(record_id) > 128:
            rejected_count += 1
            errors.append(f"Record at index {idx} has missing or invalid record_id.")
            continue

        # Zero-payload inspection
        try:
            _validate_zero_payload(rec, f"records[{idx}]")
        except ValueError as val_err:
            rejected_count += 1
            errors.append(str(val_err))
            continue

        # Check timestamp sanity (within 7 days in past, no more than 5 min in future)
        rec_time = rec.get("timestamp")
        if rec_time is not None:
            try:
                rec_time_f = float(rec_time)
                if (now - rec_time_f) > 604800 or (rec_time_f - now) > 300:
                    rejected_count += 1
                    errors.append(f"Record {record_id} has invalid or expired timestamp ({rec_time_f}).")
                    continue
            except (ValueError, TypeError):
                rejected_count += 1
                errors.append(f"Record {record_id} has non-numeric timestamp.")
                continue

        # Idempotency / Deduplication check
        if SensorIngestRepository.is_duplicate(db, sensor.sensor_id, record_id):
            duplicate_count += 1
            ack_ids.append(record_id)
            continue

        record_type = rec.get("record_type", "FLOW")
        latest_version = rec.get("sensor_version") or latest_version
        latest_hostname = rec.get("hostname") or latest_hostname

        if record_type == "FLOW":
            flow_data = rec.get("flow")
            if not flow_data or not isinstance(flow_data, dict) or "flow_id" not in flow_data:
                rejected_count += 1
                errors.append(f"Record {record_id} of type FLOW is missing valid flow dictionary.")
                continue

            # Ensure sensor_id and owner user_id attribution
            flow_data["sensor_id"] = sensor.sensor_id
            flow_data["user_id"] = sensor.user_id
            flow_data["traffic_context"] = flow_data.get("traffic_context", "REMOTE_SENSOR")
            flow_data["timestamp"] = flow_data.get("timestamp") or rec.get("timestamp") or now
            flow_data["start_time"] = flow_data.get("start_time") or flow_data["timestamp"]
            flow_data["last_seen"] = flow_data.get("last_seen") or flow_data["timestamp"]

            try:
                FlowRepository.create_or_update(db, flow_data)
                SensorIngestRepository.record_ingestion(db, sensor.sensor_id, record_id, record_type)
                accepted_count += 1
                ack_ids.append(record_id)
                batch_flows += 1
                batch_packets += int(flow_data.get("total_packets", 0))
            except Exception as e:
                db.rollback()
                logger.error(f"Error persisting ingested flow {record_id}: {e}")
                rejected_count += 1
                errors.append(f"Database error persisting flow {record_id}.")

        elif record_type == "THREAT_ALERT":
            alert_data = rec.get("detection") or {}
            flow_data = rec.get("flow") or {}

            # Construct or complete alert model payload
            alert_id = alert_data.get("alert_id") or f"alert_{record_id[-12:]}"
            complete_alert = {
                "alert_id": alert_id,
                "timestamp": rec.get("timestamp", now),
                "flow_id": alert_data.get("flow_id") or flow_data.get("flow_id", "unknown_flow"),
                "src_ip": alert_data.get("src_ip") or flow_data.get("src_ip", "0.0.0.0"),
                "dst_ip": alert_data.get("dst_ip") or flow_data.get("dst_ip", "0.0.0.0"),
                "src_port": alert_data.get("src_port") or flow_data.get("src_port"),
                "dst_port": alert_data.get("dst_port") or flow_data.get("dst_port"),
                "protocol": alert_data.get("protocol") or flow_data.get("protocol", "TCP"),
                "threat_class": alert_data.get("threat_class", "SUSPICIOUS"),
                "threat_category": alert_data.get("threat_category", "REMOTE_DETECTION"),
                "confidence": alert_data.get("confidence", 0.5),
                "confidence_band": alert_data.get("confidence_band", "LOW_CONFIDENCE"),
                "severity": alert_data.get("severity", "LOW"),
                "detector": alert_data.get("detector", "RemoteWindowsSensor"),
                "model_status": alert_data.get("model_status", "FULLY_COMPATIBLE"),
                "evidence": alert_data.get("evidence", []),
                "evidence_summary": alert_data.get("evidence_summary", "Ingested from remote sensor"),
                "recommended_action": alert_data.get("recommended_action", "Review remote host traffic"),
                "traffic_context": "REMOTE_SENSOR",
                "sensor_id": sensor.sensor_id,
                "user_id": sensor.user_id
            }

            try:
                AlertRepository.create_or_update(db, complete_alert)
                SensorIngestRepository.record_ingestion(db, sensor.sensor_id, record_id, record_type)
                accepted_count += 1
                ack_ids.append(record_id)
                batch_alerts += 1
            except Exception as e:
                db.rollback()
                logger.error(f"Error persisting ingested alert {record_id}: {e}")
                rejected_count += 1
                errors.append(f"Database error persisting alert {record_id}.")

        elif record_type in ("HEARTBEAT", "SENSOR_STATUS"):
            # Heartbeats and status reports update sensor telemetry without creating flows
            SensorIngestRepository.record_ingestion(db, sensor.sensor_id, record_id, record_type)
            accepted_count += 1
            ack_ids.append(record_id)
        else:
            rejected_count += 1
            errors.append(f"Record {record_id} has unrecognized record_type '{record_type}'.")

    # 5. Update sensor operational telemetry
    updated_sensor = None
    try:
        updated_sensor = SensorEnrollmentRepository.update_telemetry(
            db=db,
            sensor_id=sensor.sensor_id,
            last_ip=client_ip,
            sensor_version=latest_version,
            hostname=latest_hostname,
            new_packets=batch_packets,
            new_flows=batch_flows,
            new_alerts=batch_alerts,
            actual_state=body.actual_state
        )
    except Exception as tel_err:
        logger.warning(f"Failed to update sensor telemetry counters: {tel_err}")

    logger.info(
        f"Ingested batch '{body.batch_id}' from sensor '{sensor.sensor_id}': "
        f"{accepted_count} accepted, {duplicate_count} duplicate, {rejected_count} rejected."
    )

    current_target_state = updated_sensor.target_state if updated_sensor else getattr(sensor, "target_state", "STOPPED")
    current_target_iface = updated_sensor.target_interface if updated_sensor else getattr(sensor, "target_interface", None)

    return {
        "success": True,
        "sensor_id": sensor.sensor_id,
        "batch_id": body.batch_id,
        "received": len(body.records),
        "accepted": accepted_count,
        "duplicate": duplicate_count,
        "rejected": rejected_count,
        "ack_ids": ack_ids,
        "command": current_target_state,
        "target_interface": current_target_iface,
        "errors": errors[:10]  # Cap error list to prevent response bloating
    }


@router.post(
    "/enroll",
    summary="Enroll Sensor Device",
    description="Registers a new sensor device and generates a revocable API key for the authenticated user."
)
def enroll_sensor(
    payload: SensorEnrollRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enroll a new Windows sensor and issue its API key (shown only once)."""
    raw_api_key, key_hash, key_prefix = generate_sensor_api_key()

    sensor = SensorEnrollmentRepository.enroll_sensor(
        db=db,
        sensor_id=payload.sensor_id.strip().lower(),
        name=payload.name.strip(),
        api_key_hash=key_hash,
        api_key_prefix=key_prefix,
        owner_email=current_user.email,
        user_id=current_user.user_id
    )

    logger.info(f"User {current_user.email} (ID: {current_user.user_id}) enrolled sensor {sensor.sensor_id} ({sensor.name})")

    return {
        "success": True,
        "message": "Sensor enrolled successfully. Store the API key securely; it will not be displayed again.",
        "sensor": sensor.to_dict(),
        "api_key": raw_api_key
    }


@router.get(
    "/list",
    summary="List Enrolled Sensors",
    description="Lists enrolled sensor devices with connection health and telemetry scoped to the current user."
)
def list_sensors(
    status: Optional[str] = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieve enrolled sensors scoped to the authenticated user (or all if admin)."""
    if getattr(current_user, "role", None) == "admin":
        sensors = SensorEnrollmentRepository.get_all(db, status=status)
    else:
        sensors = SensorEnrollmentRepository.get_by_user(db, user_id=current_user.user_id, status=status)
    return [s.to_dict() for s in sensors]


@router.post(
    "/revoke",
    summary="Revoke Sensor Credential",
    description="Revokes an active sensor credential, immediately blocking telemetry transmission."
)
def revoke_sensor(
    payload: SensorRevokeRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a sensor's access credential. Users can only revoke their own sensors unless admin."""
    sensor = SensorEnrollmentRepository.get_by_sensor_id(db, payload.sensor_id)
    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor '{payload.sensor_id}' not found."
        )

    if getattr(current_user, "role", None) != "admin" and sensor.user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to revoke this sensor."
        )

    revoked = SensorEnrollmentRepository.revoke_sensor(db, payload.sensor_id)
    if not revoked:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor '{payload.sensor_id}' not found."
        )

    logger.warning(f"User {current_user.email} revoked sensor credential: {payload.sensor_id}")
    return {
        "success": True,
        "message": f"Sensor '{payload.sensor_id}' has been revoked."
    }


@router.post(
    "/{sensor_id}/control",
    summary="Control Remote Sensor Capture",
    description="Issues an authenticated, owner-scoped START or STOP command to an enrolled remote sensor device."
)
def control_sensor(
    sensor_id: str,
    payload: SensorControlRequest,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Queue an operational control command (START or STOP) for a remote Windows sensor.
    Enforces strict ownership: User A cannot start, stop, or configure User B's sensor.
    """
    sensor = SensorEnrollmentRepository.get_by_sensor_id(db, sensor_id)
    if not sensor:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sensor '{sensor_id}' not found."
        )

    # Cross-user isolation: verify caller owns this sensor (or is administrator)
    if getattr(current_user, "role", None) != "admin" and sensor.user_id != current_user.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have permission to control this sensor."
        )

    if sensor.status == "REVOKED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sensor '{sensor_id}' has been revoked and cannot receive commands."
        )

    target_cmd = "RUNNING" if payload.command == "START" else "STOPPED"
    updated = SensorEnrollmentRepository.set_target_state(
        db,
        sensor_id=sensor_id,
        target_state=target_cmd,
        target_interface=payload.interface
    )

    logger.info(
        f"User {current_user.email} issued command '{payload.command}' to sensor '{sensor_id}' "
        f"(interface: {payload.interface or 'default'})."
    )

    return {
        "success": True,
        "message": f"Command '{payload.command}' queued for sensor '{sensor_id}'. Awaiting agent confirmation.",
        "sensor_id": sensor_id,
        "command": payload.command,
        "target_state": updated.target_state if updated else target_cmd,
        "actual_state": updated.actual_state if updated else "UNKNOWN"
    }


@router.get(
    "/events",
    summary="Stream Remote Sensor Events",
    description="Retrieves live stream events observed by enrolled remote sensors with explicit source attribution."
)
def get_sensor_events(
    sensor_id: Optional[str] = None,
    limit: int = 30,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns recent flow observations and alerts ingested from remote sensors,
    formatted identically to LiveStreamEventItem with sensor attribution.
    Scoped to the current user unless admin.
    """
    safe_limit = min(max(1, limit), 100)
    user_scope = None if getattr(current_user, "role", None) == "admin" else current_user.user_id

    # Query recent flows with sensor_id
    flows, _ = FlowRepository.get_flows(db, limit=safe_limit, sensor_id=sensor_id, user_id=user_scope)

    # Map flows to LiveStreamEventItem format
    events = []
    for f in flows:
        if not f.sensor_id:
            continue
        events.append({
            "id": f"remote-evt-{int(f.start_time * 1000)}-{f.flow_id[-6:]}",
            "timestamp": int(f.last_seen * 1000),
            "flow_id": f.flow_id,
            "src_ip": f.src_ip,
            "dst_ip": f.dst_ip,
            "dst_port": f.dst_port,
            "protocol": f.protocol,
            "packets": f.total_packets,
            "bytes": f.total_bytes,
            "threat_outcome": "BENIGN",  # Enriched if alert exists
            "severity": "BENIGN",
            "alert_id": None,
            "sensor_id": f.sensor_id,
            "source": f"SENSOR:{f.sensor_id}"
        })

    return events[:safe_limit]


@router.get(
    "/download/windows-agent",
    summary="Download Windows Sensor Agent Package",
    description="Packages and serves a self-contained ZIP archive containing the ThreatTrack Windows Sensor agent, double-clickable launcher, UAC elevation script, and documentation."
)
def download_windows_sensor(
    request: Request,
    sensor_id: Optional[str] = None,
    api_key: Optional[str] = None,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Builds a standalone ThreatTrack Windows Sensor distribution ZIP.
    If sensor_id is provided, verifies ownership and pre-populates sensor_config.json.
    """
    if sensor_id:
        sensor = SensorEnrollmentRepository.get_by_sensor_id(db, sensor_id)
        if not sensor:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Sensor '{sensor_id}' not found.")
        if getattr(current_user, "role", None) != "admin" and sensor.user_id != current_user.user_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Forbidden: You do not have permission to download this sensor package.")

    backend_url = f"{request.url.scheme}://{request.url.netloc}"
    backend_dir = Path(__file__).resolve().parent.parent.parent

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. start_sensor.bat
        start_bat = (
            "@echo off\r\n"
            "setlocal\r\n"
            "cd /d \"%~dp0\"\r\n"
            "title ThreatTrack Local Windows Sensor Launcher\r\n\r\n"
            ":: 1. Verify / Request Windows Administrator Elevation (Required for Npcap socket binding)\r\n"
            "net session >nul 2>&1\r\n"
            "if %errorlevel% neq 0 (\r\n"
            "    echo [*] Windows packet capture requires Administrator privileges.\r\n"
            "    echo [*] Requesting UAC elevation...\r\n"
            "    powershell -Command \"Start-Process cmd -ArgumentList '/k \"\"%~f0\"\"' -Verb RunAs\"\r\n"
            "    exit /b\r\n"
            ")\r\n\r\n"
            ":: 2. Verify Python Installation\r\n"
            "where python >nul 2>&1\r\n"
            "if %errorlevel% neq 0 (\r\n"
            "    echo [X] Python was not found on your system PATH.\r\n"
            "    echo [*] Please install Python 3.9+ from https://www.python.org/downloads/\r\n"
            "    echo [*] Ensure 'Add Python to PATH' is checked during installation.\r\n"
            "    pause\r\n"
            "    exit /b\r\n"
            ")\r\n\r\n"
            ":: 3. Verify Npcap Driver\r\n"
            "if not exist \"%SystemRoot%\\System32\\Npcap\" (\r\n"
            "    if not exist \"%SystemRoot%\\System32\\wpcap.dll\" (\r\n"
            "        echo [!] WARNING: Npcap packet capture driver was not detected.\r\n"
            "        echo [*] Passive packet sniffing requires Npcap (https://npcap.com/#download).\r\n"
            "        echo [*] Opening Npcap download page in browser...\r\n"
            "        start https://npcap.com/#download\r\n"
            "        echo [*] Please install Npcap with 'Install Npcap in WinPcap API-compatible Mode' enabled.\r\n"
            "        pause\r\n"
            "    )\r\n"
            ")\r\n\r\n"
            ":: 4. Verify / Install Dependencies\r\n"
            "python -c \"import scapy\" >nul 2>&1\r\n"
            "if %errorlevel% neq 0 (\r\n"
            "    echo [*] Installing required sensor dependencies (scapy)...\r\n"
            "    pip install -r requirements.txt\r\n"
            "    if %errorlevel% neq 0 (\r\n"
            "        echo [X] Dependency installation failed. Check internet connection.\r\n"
            "        pause\r\n"
            "        exit /b\r\n"
            ")\r\n\r\n"
            ":: 5. Launch ThreatTrack Sensor\r\n"
            "echo [*] Launching ThreatTrack Sensor Engine...\r\n"
            "python -m src.sensor.cli\r\n"
            "if %errorlevel% neq 0 (\r\n"
            "    echo [!] Sensor exited with status code %errorlevel%.\r\n"
            "    pause\r\n"
            ")\r\n"
        )
        zf.writestr("ThreatTrack-Sensor/start_sensor.bat", start_bat)

        # 2. launch_elevated.ps1
        launch_ps1 = (
            "<#\r\n"
            ".SYNOPSIS\r\n"
            "    ThreatTrack Elevated Windows Sensor Launcher\r\n"
            "#>\r\n"
            "$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path\r\n"
            "Set-Location $scriptDir\r\n"
            "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)\r\n"
            "if (-not $isAdmin) {\r\n"
            "    Write-Host '[*] Requesting UAC elevation...' -ForegroundColor Yellow\r\n"
            "    Start-Process powershell -Verb RunAs -ArgumentList \"-NoExit -ExecutionPolicy Bypass -File `\"$($MyInvocation.MyCommand.Path)`\"\"\r\n"
            "    exit\r\n"
            "}\r\n"
            "python -m src.sensor.cli\r\n"
        )
        zf.writestr("ThreatTrack-Sensor/launch_elevated.ps1", launch_ps1)

        # 3. requirements.txt
        zf.writestr("ThreatTrack-Sensor/requirements.txt", "scapy>=2.5.0\r\nurllib3>=1.26.0\r\n")

        # 4. sensor_config.json
        cfg_dict = {
            "sensor_id": sensor_id or "",
            "api_key": api_key or "",
            "backend_url": backend_url
        }
        zf.writestr("ThreatTrack-Sensor/sensor_config.json", json.dumps(cfg_dict, indent=2))

        # 5. README.txt
        readme_content = (
            "========================================================================\r\n"
            "   ThreatTrack Local Windows Sensor - Quick Setup Guide\r\n"
            "   SIH Problem Statement 26145: AI-Based Threat Detection (Unidirectional)\r\n"
            "========================================================================\r\n\r\n"
            "REQUIREMENTS:\r\n"
            "1. Windows 10 or Windows 11 (64-bit)\r\n"
            "2. Python 3.9+ (from https://www.python.org/downloads/)\r\n"
            "3. Npcap Driver (from https://npcap.com/#download)\r\n\r\n"
            "HOW TO RUN:\r\n"
            "1. Ensure Npcap is installed with 'WinPcap API-compatible Mode' enabled.\r\n"
            "2. Double-click 'start_sensor.bat'. When Windows asks for UAC permission, click 'Yes'.\r\n"
            "3. Return to your web dashboard. Your computer will be detected and ready for Live Monitoring!\r\n\r\n"
            "SAFETY & PRIVACY GUARANTEE:\r\n"
            "- Passive, read-only packet capture only. Zero packet injection or probing.\r\n"
            "- Metadata only: no packet payloads, passwords, or raw bytes are stored or transmitted.\r\n"
            "- Telemetry is strictly isolated and accessible only to your authenticated user account.\r\n"
        )
        zf.writestr("ThreatTrack-Sensor/README.txt", readme_content)

        # 6. Bundle source code required by the sensor
        src_root = backend_dir / "src"
        modules_to_bundle = ["sensor", "capture", "detection", "alerts"]
        zf.writestr("ThreatTrack-Sensor/src/__init__.py", "")

        for mod in modules_to_bundle:
            mod_dir = src_root / mod
            if mod_dir.is_dir():
                for py_file in mod_dir.glob("*.py"):
                    if not py_file.name.startswith("test_"):
                        arc_path = f"ThreatTrack-Sensor/src/{mod}/{py_file.name}"
                        zf.writestr(arc_path, py_file.read_bytes())

    buf.seek(0)
    zip_bytes = buf.getvalue()

    filename = f"ThreatTrack-Sensor-{sensor_id}.zip" if sensor_id else "ThreatTrack-Windows-Sensor.zip"
    return Response(
        content=zip_bytes,
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(zip_bytes))
        }
    )

