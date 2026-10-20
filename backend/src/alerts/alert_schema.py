"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.alerts.alert_schema

Defines standard schemas for detector outputs, supporting evidence items, and unified threat alerts.
Strictly metadata-only and analyst-oriented.
"""

from dataclasses import dataclass, asdict, field
from typing import Optional, Dict, Any, List
import json
import math


@dataclass
class ThreatEvidenceItem:
    """Represents a single verifiable piece of supporting evidence derived from computed flow features."""
    feature: str
    value: Any
    threshold: Optional[float]
    direction: Optional[str]  # 'above', 'below', 'equal', 'matches'
    explanation: str

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if isinstance(d['value'], float):
            d['value'] = round(d['value'], 4) if not math.isnan(d['value']) else 0.0
        if isinstance(d['threshold'], float) and d['threshold'] is not None:
            d['threshold'] = round(d['threshold'], 4) if not math.isnan(d['threshold']) else None
        return d


@dataclass
class DetectorResult:
    """Normalized output from an individual threat detection model."""
    detector: str                          # e.g., 'RandomForest_DDoS', 'PCA_Botnet_C2', 'IsolationForest_PortScan'
    threat_class: str                      # 'DDoS', 'BOTNET_C2', 'RECON_PORTSCAN', 'BENIGN'
    prediction: int                        # 1 (threat) or 0 (normal)
    score: Optional[float] = None          # Continuous anomaly score / distance (not necessarily probability)
    confidence: Optional[float] = None     # Calibrated probability (0.0 - 1.0) if supported, else None
    confidence_band: str = "LOW_CONFIDENCE"  # 'LOW_CONFIDENCE', 'MEDIUM_CONFIDENCE', 'HIGH_CONFIDENCE', 'NOT_APPLICABLE'
    compatible: str = "FULLY_COMPATIBLE"   # 'FULLY_COMPATIBLE', 'PARTIALLY_COMPATIBLE', 'NOT_COMPATIBLE'
    status: str = "READY"                  # 'READY', 'INSUFFICIENT_HISTORY'
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    reason: str = ""


@dataclass
class ThreatAlert:
    """
    Standardized, human-auditable threat alert generated for SIH Problem Statement 26145.
    Contains flow 5-tuple metadata, threat classification, confidence, explainable evidence,
    traffic context, and analyst-oriented recommended actions.
    """
    alert_id: str
    timestamp: float

    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str

    threat_class: str                      # 'DDoS', 'BOTNET_C2', 'RECON_PORTSCAN', 'MULTI_THREAT', 'BENIGN'
    threat_category: str                   # 'DDoS', 'BOTNET_C2', 'RECON_PORTSCAN', 'DGA_DNS_TUNNEL', etc.

    confidence: Optional[float]            # Calibrated probability or continuous suspicion score
    confidence_band: str = "LOW_CONFIDENCE"  # 'LOW_CONFIDENCE', 'MEDIUM_CONFIDENCE', 'HIGH_CONFIDENCE', 'NOT_APPLICABLE'
    severity: str = "LOW"                  # 'BENIGN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    traffic_context: str = "UNLABELED_LIVE"  # 'LAB_ATTACK', 'LAB_BENIGN', 'REPLAY', 'UNLABELED_LIVE', 'PRODUCTION_MONITORING'

    detector: str = "MultiThreatEnsemble"  # Name(s) of detecting model(s)
    model_status: str = "FULLY_COMPATIBLE" # 'FULLY_COMPATIBLE', 'PARTIALLY_COMPATIBLE', 'NOT_COMPATIBLE'

    evidence: List[Dict[str, Any]] = field(default_factory=list)         # Structured list of supporting evidence items
    evidence_summary: str = ""             # Compact human-readable explanation

    flow_duration: float = 0.0
    total_packets: int = 0
    total_bytes: int = 0

    recommended_action: str = ""           # Passive analyst-oriented next step

    def to_dict(self) -> Dict[str, Any]:
        """Convert alert to a serializable dictionary with safe float rounding."""
        d = asdict(self)
        if d['confidence'] is not None:
            d['confidence'] = round(d['confidence'], 4) if not math.isnan(d['confidence']) else 0.0
        d['flow_duration'] = round(d['flow_duration'], 4)
        return d

    def to_json(self) -> str:
        """Convert alert to a JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ThreatAlert":
        """Reconstruct a ThreatAlert from a dictionary."""
        return cls(**data)
