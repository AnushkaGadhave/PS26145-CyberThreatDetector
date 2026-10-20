"""
NETRA Local Windows Sensor - Configuration Module
Defines runtime configurations for network sniffing, flow aggregation,
feature validation, and the local metadata queue.
"""

import os
import uuid
import socket
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, Dict, Any


def get_default_sensor_id() -> str:
    """Generate a stable or identifiable default sensor ID for this host."""
    hostname = socket.gethostname() or "win-host"
    return f"netra-sensor-{hostname.lower()}"


@dataclass
class SensorConfig:
    """Configuration settings for the NETRA Windows Sensor."""
    interface: Optional[str] = None
    duration: Optional[float] = None  # None = continuous capture until stopped
    flow_timeout: float = 30.0        # Seconds of inactivity before flow expiration
    flow_flush_interval: float = 3.0  # Periodic sweep interval for flow eviction
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
            "suppression_window_seconds": self.suppression_window_seconds
        }
