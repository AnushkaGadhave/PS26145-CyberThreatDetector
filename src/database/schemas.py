"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.database.schemas

Pydantic schemas for API request validation and response serialization.
Strictly metadata-only: guarantees no packet payloads or raw bytes are accepted or exposed.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field


class HealthResponse(BaseModel):
    """Health status response."""
    status: str = "ok"
    service: str = "PS26145 API"


class FlowResponse(BaseModel):
    """Network flow metadata representation."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    flow_id: str
    timestamp: float
    start_time: float
    last_seen: float

    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

    duration: float
    total_packets: int
    total_bytes: int

    forward_packets: int = 0
    backward_packets: int = 0
    forward_bytes: int = 0
    backward_bytes: int = 0

    packets_per_second: float = 0.0
    bytes_per_second: float = 0.0

    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_min: float = 0.0
    iat_max: float = 0.0

    traffic_context: str = "UNLABELED_LIVE"
    created_at: Optional[str] = None


class FlowListResponse(BaseModel):
    """Paginated flows list response."""
    total: int
    limit: int
    offset: int
    flows: List[FlowResponse]


class AlertResponse(BaseModel):
    """Threat detection alert representation."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    alert_id: str
    timestamp: float
    flow_id: str

    src_ip: str
    dst_ip: str
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str

    threat_class: str
    threat_category: str

    confidence: Optional[float] = None
    confidence_band: str = "LOW_CONFIDENCE"
    severity: str

    detector: str
    model_status: str

    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    evidence_summary: str = ""

    recommended_action: str = ""
    traffic_context: str = "UNLABELED_LIVE"
    created_at: Optional[str] = None


class AlertListResponse(BaseModel):
    """Paginated alerts list response."""
    total: int
    limit: int
    offset: int
    alerts: List[AlertResponse]


class AlertSummaryResponse(BaseModel):
    """Aggregated threat metrics for dashboard."""
    total_alerts: int
    total_flows: int
    benign_count: int
    low_count: int
    medium_count: int
    high_count: int
    critical_count: int

    ddos_count: int
    botnet_c2_count: int
    recon_portscan_count: int
    multi_threat_count: int

    unlabeled_live_alerts: int


class ModelStatusResponse(BaseModel):
    """Model operational status representation."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    model_name: str
    status: str
    compatible: str
    reason: str
    updated_at: Optional[str] = None


class TopIPItem(BaseModel):
    """Top communicating IP address with count."""
    ip: str
    count: int


class DashboardOverviewResponse(BaseModel):
    """Complete dashboard telemetry snapshot."""
    total_flows: int
    total_alerts: int

    alerts_last_5_minutes: int
    alerts_last_15_minutes: int
    alerts_last_24_hours: int

    severity_counts: Dict[str, int]
    threat_counts: Dict[str, int]

    top_source_ips: List[TopIPItem]
    top_destination_ips: List[TopIPItem]
    protocol_counts: Dict[str, int]

    model_status: List[ModelStatusResponse]
