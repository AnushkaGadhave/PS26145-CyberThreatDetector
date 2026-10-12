"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Package: src.capture

Provides passive, read-only packet sniffing and real-time bidirectional flow construction.
"""

from src.capture.flow_schema import FlowRecord
from src.capture.flow_builder import FlowBuilder
from src.capture.live_capture import (
    capture_packets,
    extract_packet_metadata,
    DEFAULT_INTERFACE,
    DEFAULT_CAPTURE_DURATION,
    FLOW_TIMEOUT_SECONDS,
    FLUSH_INTERVAL_SECONDS,
    DEFAULT_JSONL_PATH
)

__all__ = [
    "FlowRecord",
    "FlowBuilder",
    "capture_packets",
    "extract_packet_metadata",
    "DEFAULT_INTERFACE",
    "DEFAULT_CAPTURE_DURATION",
    "FLOW_TIMEOUT_SECONDS",
    "FLUSH_INTERVAL_SECONDS",
    "DEFAULT_JSONL_PATH"
]
