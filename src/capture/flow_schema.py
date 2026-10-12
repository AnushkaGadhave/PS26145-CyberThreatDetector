"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.flow_schema

Defines the structured schema for network flow records and derived flow-level features.
Adheres strictly to passive metadata extraction (zero payload storage).
"""

from dataclasses import dataclass, asdict
from typing import Optional, Dict, Any
import json
import math


@dataclass
class FlowRecord:
    """
    Represents a finalized bidirectional network flow record.
    All fields are pure metadata derived from packet headers and timing.
    Zero application payloads or decrypted contents are stored.
    """
    # Flow Identifiers
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str  # 'TCP', 'UDP', 'ICMP', etc.

    # Temporal Bounds
    start_time: float      # Unix epoch timestamp of first observed packet
    last_seen: float       # Unix epoch timestamp of last observed packet
    duration: float        # Total flow active duration in seconds (last_seen - start_time)

    # Volumetric Statistics
    total_packets: int
    total_bytes: int
    forward_packets: int
    backward_packets: int
    forward_bytes: int
    backward_bytes: int

    # Rate & Ratio Features (Safe Division Applied)
    packets_per_second: float
    bytes_per_second: float
    forward_packet_ratio: float
    backward_packet_ratio: float
    forward_byte_ratio: float
    backward_byte_ratio: float
    bytes_per_packet: float
    packets_per_byte: float

    # TCP Flag Counts (0 for non-TCP protocols)
    syn_count: int = 0
    ack_count: int = 0
    fin_count: int = 0
    rst_count: int = 0
    psh_count: int = 0
    urg_count: int = 0

    # Inter-Arrival Time (IAT) Statistics (in seconds)
    iat_mean: float = 0.0
    iat_std: float = 0.0
    iat_min: float = 0.0
    iat_max: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert the flow record to a clean, serializable dictionary."""
        d = asdict(self)
        # Ensure all floats are finite and JSON-compliant
        for k, v in d.items():
            if isinstance(v, float):
                if math.isnan(v) or math.isinf(v):
                    d[k] = 0.0
                else:
                    d[k] = round(v, 6)
        return d

    def to_json(self) -> str:
        """Convert the flow record to a single-line JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FlowRecord":
        """Reconstruct a FlowRecord from a dictionary."""
        return cls(**data)
