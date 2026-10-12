"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Package: src.alerts

Unified threat alert generation, explainable evidence construction, policy-based severity assignment,
and streaming alert persistence.
"""

from src.alerts.alert_schema import ThreatAlert, DetectorResult, ThreatEvidenceItem
from src.alerts.evidence_builder import EvidenceBuilder
from src.alerts.alert_engine import AlertEngine
from src.alerts.alert_writer import AlertWriter
from src.alerts.alert_pipeline import AlertPipeline

__all__ = [
    "ThreatAlert",
    "DetectorResult",
    "ThreatEvidenceItem",
    "EvidenceBuilder",
    "AlertEngine",
    "AlertWriter",
    "AlertPipeline"
]
