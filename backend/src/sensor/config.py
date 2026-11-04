"""
NETRA Local Windows Sensor - Configuration Module
Defines runtime configurations for network sniffing, flow aggregation,
feature validation, and the local metadata queue.
"""

import os
import uuid
import socket
import urllib.parse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


def mask_api_key(key: Optional[str]) -> str:
    """Masks API key for safe display in logs and telemetry."""
    if not key:
        return "(none)"
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"


def validate_telemetry_backend_url(url: str, enable_remote: bool = True) -> str:
    """
    Enforces HTTPS for remote telemetry transmission.
    Rejects plain HTTP for remote hosts.
    Allows loopback addresses (127.0.0.1, localhost, ::1) only for local testing.
    """
    if not url:
        raise ValueError("Backend URL cannot be empty.")
    parsed = urllib.parse.urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme not in ("http", "https"):
        raise ValueError(
            f"Invalid URL scheme '{scheme}' in '{url}'. Remote telemetry transmission requires HTTPS."
        )

    is_loopback = host in ("127.0.0.1", "localhost", "::1", "testserver")
    if enable_remote and not is_loopback and scheme != "https":
        raise ValueError(
            f"Insecure remote telemetry transmission rejected: Backend URL '{url}' must use HTTPS. "
            f"Plain HTTP is forbidden for remote servers."
        )
    return url.strip()


def get_default_sensor_id() -> str:
    """Generate a stable or identifiable default sensor ID for this host."""
    hostname = socket.gethostname() or "win-host"
    return f"netra-sensor-{hostname.lower()}"


@dataclass
class SensorConfig:
    """Configuration settings for the NETRA Windows Sensor."""
    interface: Optional[str] = None
    duration: Optional[float] = None  # None = continuous capture until stopped
    flow_timeout: float = 15.0        # Seconds of inactivity before flow expiration (optimized from 30.0s)
    flow_flush_interval: float = 2.0  # Periodic sweep interval for flow eviction (optimized from 3.0s)
    packet_limit: Optional[int] = None

    # Queue & Spool Settings
    queue_max_size: int = 10000
    queue_spool_dir: str = "data/sensor_queue"
    spool_filename: str = "metadata_spool.jsonl"
    enable_spooling: bool = True

    # Feature & Detection Settings
    enable_feature_validation: bool = True
    enable_detection: bool = True
    traffic_context: str = "UNLABELED_LIVE"
    suppression_window_seconds: float = 15.0

    # Model artifact paths (relative or absolute)
    ddos_config_path: str = "models/ddos/ddos_model_config.json"
    ddos_model_path: str = "models/ddos/random_forest.pkl"
    portscan_config_path: str = "models/portscan/portscan_model_config.json"
    portscan_model_path: str = "models/portscan/isolation_forest.pkl"
    c2_models_dir: str = "models/c2"

    # Identity
    sensor_id: str = field(default_factory=get_default_sensor_id)
    sensor_version: str = "1.0.0-win"

    # Remote Ingestion & Cloud Transmission
    enable_remote_transmission: bool = False
    remote_backend_url: str = "http://127.0.0.1:8000"
    sensor_api_key: Optional[str] = field(default=None, repr=False)
    transmission_batch_size: int = 25
    transmission_interval: float = 1.0

    def __post_init__(self):
        """Validate configuration parameters upon initialization."""
        if self.enable_remote_transmission and self.remote_backend_url:
            self.remote_backend_url = validate_telemetry_backend_url(
                self.remote_backend_url,
                enable_remote=self.enable_remote_transmission
            )

    def to_dict(self) -> Dict[str, Any]:
        """Return dictionary representation of sensor configuration."""
        return {
            "sensor_id": self.sensor_id,
            "sensor_version": self.sensor_version,
            "interface": self.interface,
            "duration": self.duration,
            "flow_timeout": self.flow_timeout,
            "flow_flush_interval": self.flow_flush_interval,
            "packet_limit": self.packet_limit,
            "queue_max_size": self.queue_max_size,
            "queue_spool_dir": self.queue_spool_dir,
            "spool_filename": self.spool_filename,
            "enable_spooling": self.enable_spooling,
            "enable_feature_validation": self.enable_feature_validation,
            "enable_detection": self.enable_detection,
            "traffic_context": self.traffic_context,
            "suppression_window_seconds": self.suppression_window_seconds,
            "enable_remote_transmission": self.enable_remote_transmission,
            "remote_backend_url": self.remote_backend_url,
            "transmission_batch_size": self.transmission_batch_size,
            "transmission_interval": self.transmission_interval
        }
