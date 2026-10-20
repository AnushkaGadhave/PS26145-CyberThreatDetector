"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_capture

FastAPI routes for controlling passive live network capture, discovering network interfaces,
inspecting real-time capture health, and streaming observed live events.
Requires authentication; sensor activation and deactivation strictly require Administrator role.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Request, Depends, HTTPException, status

from src.capture.capture_service import capture_manager
from src.database.models import UserModel
from src.auth.dependencies import get_current_user, require_admin

router = APIRouter(prefix="/api/capture", tags=["Live Passive Capture"])


class StartCaptureRequest(BaseModel):
    interface: Optional[str] = Field(
        None,
        description="Name of the network interface to sniff (e.g., 'Wi-Fi 3'). If None, auto-selects active IP adapter."
    )


def verify_local_access(request: Request):
    """
    Restricts administrative packet-capture controls to local calls.
    Prevents unauthorized remote callers from toggling sensor capture.
    """
    client_host = request.client.host if request.client else "unknown"
    allowed_hosts = {"127.0.0.1", "::1", "localhost", "testclient"}
    if client_host not in allowed_hosts:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Packet capture controls are restricted to authorized local administrative access."
        )


@router.get(
    "/status",
    summary="Get Live Capture Status",
    description="Returns the current operational state, interface, volumetric packet counters, and flow statistics."
)
def get_capture_status(
    current_user: UserModel = Depends(get_current_user)
):
    """Return the operational health and metrics of the live packet capture worker."""
    return capture_manager.get_status()


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
    description="Spawns the background Scapy capture worker. Strictly restricted to Administrator role."
)
def start_capture(
    request: Request,
    body: StartCaptureRequest,
    current_admin: UserModel = Depends(require_admin)
):
    """Start passive read-only sniffing and real-time flow aggregation."""
    verify_local_access(request)
    result = capture_manager.start(body.interface)
    if not result.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("message", "Failed to start capture.")
        )
    return result


@router.post(
    "/stop",
    summary="Stop Passive Live Capture",
    description="Gracefully halts the packet sniffer. Strictly restricted to Administrator role."
)
def stop_capture(
    request: Request,
    current_admin: UserModel = Depends(require_admin)
):
    """Stop live packet capture and finalize active network flows."""
    verify_local_access(request)
    result = capture_manager.stop()
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
    """Fetch recent live stream events for real-time frontend monitoring display."""
    safe_limit = min(max(1, limit), 100)
    return capture_manager.get_recent_events(limit=safe_limit)
