"""
NETRA Local Windows Sensor Package
Provides modular passive packet capture, bidirectional flow aggregation,
feature validation against trained models, and local metadata queueing
for future cloud telemetry delivery.
"""

from src.sensor.config import SensorConfig
from src.sensor.interface_manager import (
    InterfaceManager,
    NetworkInterfaceDetails,
    InterfaceNotFoundError
)
from src.sensor.metadata_queue import LocalMetadataQueue, MetadataRecord
from src.sensor.feature_validator import FeatureValidator, ValidationResult
from src.sensor.safety import (
    evaluate_multicast_discovery_safety,
    prevent_c2_multicast_misclassification
)
from src.sensor.windows_sensor import (
    WindowsSensor,
    CaptureError,
    CapturePermissionError,
    InterfaceUnavailableError
)

__all__ = [
    "SensorConfig",
    "InterfaceManager",
    "NetworkInterfaceDetails",
    "InterfaceNotFoundError",
    "LocalMetadataQueue",
    "MetadataRecord",
    "FeatureValidator",
    "ValidationResult",
    "WindowsSensor",
    "CaptureError",
    "CapturePermissionError",
    "InterfaceUnavailableError",
    "evaluate_multicast_discovery_safety",
    "prevent_c2_multicast_misclassification"
]
