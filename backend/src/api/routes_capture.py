"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_capture

FastAPI routes for controlling passive live network capture, discovering network interfaces,
inspecting real-time capture health, and streaming observed live events.
Supports per-user local monitoring: any registered user on the local host can monitor
their own interface with full data isolation. Cross-user capture control is strictly forbidden.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Request, Depends, HTTPException, status

from src.capture.capture_service import capture_manager
from src.database.models import UserModel
from src.auth.dependencies import get_current_user

router = APIRouter(prefix="/api/capture", tags=["Live Passive Capture"])


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = Field(
        None,
        description="Name of the network interface to sniff (e.g., 'Wi-Fi 3'). If None, auto-selects active IP adapter."
    )


import os

def is_direct_localhost_request(request: Request) -> bool:
    """
    Determines if request is genuinely from a local development client.
    Guarantees:
    1. If NETRA_HOSTED or HOSTED_MODE environment variable is set ('true', '1', 'yes'),
       the server is hosted; local hardware capture is NEVER allowed.
    2. Never trusts arbitrary forwarded headers (X-Forwarded-For, X-Real-IP) to claim
       localhost privileges if the underlying socket client is not local.
    3. If any forwarded header indicates an external client, it is treated as remote.
    """
    if os.getenv("THREATTRACK_HOSTED", "").lower() in ("true", "1", "yes") or \
       os.getenv("NETRA_HOSTED", "").lower() in ("true", "1", "yes") or \
       os.getenv("HOSTED_MODE", "").lower() in ("true", "1", "yes") or \
       os.getenv("DISABLE_SERVER_CAPTURE", "").lower() in ("true", "1", "yes"):
        return False

    # Check direct TCP socket peer
    direct_peer = request.client.host if request.client else ""
    local_peers = {"127.0.0.1", "::1", "localhost", "testclient"}
    if direct_peer not in local_peers:
        return False

    # Inspect forwarded headers: if ANY forwarded header is present with an external IP,
    # the client is behind a reverse proxy and is external.
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
        for ip in parts:
            if ip not in local_peers:
                return False

    real_ip = request.headers.get("x-real-ip")
    if real_ip and real_ip.strip() not in local_peers:
        return False

    return True


def verify_local_access(request: Request):
    """
    Restricts direct hardware packet-capture controls to the local machine.
    Prevents a browser running on a remote device from accidentally capturing the server's NIC.
    Remote devices must run their own local Windows sensor instance.
    """
    if not is_direct_localhost_request(request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Direct server packet capture controls are restricted to the local host (development mode). "
                "In a hosted deployment or from a remote device, you must enroll and run the "
                "ThreatTrack local sensor on your computer."
            )
        )


@router.get(
    "/status",
    summary="Get Live Capture Status",
    description="Returns the operational state, interface, volumetric packet counters, and rich health diagnostics."
)
def get_capture_status(
    request: Request,
    current_user: UserModel = Depends(get_current_user)
):
    """Return the operational health and metrics of the live packet capture worker."""
    is_local = is_direct_localhost_request(request)
    is_admin = getattr(current_user, "role", "") == "admin"
    status_dict = capture_manager.get_status(user_id=current_user.user_id, is_admin=is_admin)
    status_dict["is_local_client"] = is_local
    return status_dict


@router.get(
    "/interfaces",
    summary="List Available Network Interfaces",
    description="Discovers physical and virtual network adapters available on the host via Scapy/Npcap."
)
def list_interfaces(
    current_user: UserModel = Depends(get_current_user)
):
    """List host network interfaces with assigned IPs and connection status."""
    return capture_manager.get_available_interfaces()


@router.post(
    "/start",
    summary="Start Passive Live Capture",
    description="Spawns the background Scapy capture worker for the authenticated user on their local interface."
)
def start_capture(
    request: Request,
    body: StartCaptureRequest,
    current_user: UserModel = Depends(get_current_user)
):
    """Start passive read-only sniffing and real-time flow aggregation stamped with user ownership."""
    verify_local_access(request)
    result = capture_manager.start(body.interface, user_id=current_user.user_id)
    if not result.get("success"):
        code = result.get("code")
        if code == "OCCUPIED_BY_ANOTHER_USER":
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=result.get("message", "Local network adapter is in use by another session.")
            )
        elif code == "PERMISSION_REQUIRED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=result.get("message", "Administrator privileges or Npcap elevation required.")
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("message", "Failed to start capture.")
        )
    return result


@router.post(
    "/stop",
    summary="Stop Passive Live Capture",
    description="Gracefully halts the packet sniffer. Users can stop their own session; administrators can stop any active session."
)
def stop_capture(
    request: Request,
    current_user: UserModel = Depends(get_current_user)
):
    """Stop live packet capture and finalize active network flows."""
    verify_local_access(request)
    is_admin = getattr(current_user, "role", "") == "admin"
    result = capture_manager.stop(user_id=current_user.user_id, is_admin=is_admin)
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=result.get("message", "Failed to stop capture.")
        )
    return result


@router.get(
    "/events",
    summary="Stream Recent Live Events",
    description="Retrieves the most recent live flow and detection events observed during the active session."
)
def get_recent_live_events(
    limit: int = 30,
    current_user: UserModel = Depends(get_current_user)
):
    """Fetch recent live stream events for real-time frontend monitoring display, scoped to authenticated user."""
    safe_limit = min(max(1, limit), 100)
    user_scope = None if getattr(current_user, "role", "") == "admin" else current_user.user_id
    return capture_manager.get_recent_events(limit=safe_limit, user_id=user_scope)
