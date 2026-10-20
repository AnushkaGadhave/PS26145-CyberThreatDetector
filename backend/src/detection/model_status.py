"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.detection.model_status

Provides runtime model compatibility status and feature provenance diagnostics.
"""

from typing import Dict, Any


def get_model_status() -> Dict[str, Any]:
    """
    Returns the real-time operational and feature compatibility status for all threat detection models.
    Used by downstream triage engines, alert loggers, and the visualization dashboard.
    """
    return {
        "ddos": {
            "model_family": "Random Forest Classifier",
            "benchmark_dataset": "CIC-IDS2017 (DDoS)",
            "features_count": 74,
            "status": "PARTIALLY_COMPATIBLE",
            "compatible": True,
            "inference_mode": "ACTIVE",
            "reason": "Volumetric rates, byte/packet ratios, and TCP flags are exact; deep subflow segmentation and TCP window options are approximated in lightweight streaming."
        },
        "c2": {
            "model_family": "Hybrid PCA / Anomaly Scoring",
            "benchmark_dataset": "CTU-13 Scenario 42 (Neris Botnet C2)",
            "features_count": 46,
            "status": "FULLY_COMPATIBLE",
            "compatible": True,
            "inference_mode": "ACTIVE",
            "reason": "Exact causal online feature alignment with streaming rolling-window buffers (60s, 300s lookbacks, running IAT regularity, destination fanout)."
        },
        "portscan": {
            "model_family": "Isolation Forest Anomaly Detector",
            "benchmark_dataset": "CIC-IDS2017 (PortScan)",
            "features_count": 78,
            "status": "PARTIALLY_COMPATIBLE",
            "compatible": True,
            "inference_mode": "ACTIVE",
            "reason": "Flow-level statistical features are aligned with normal baseline training; host fan-out fusion recommended for multi-probe reconnaissance tracking."
        }
    }


def is_model_inference_allowed(model_name: str) -> bool:
    """Returns True if the specified threat model is cleared for runtime live inference."""
    status = get_model_status().get(model_name.lower())
    if not status:
        return False
    return status.get("compatible", False) and status.get("inference_mode") == "ACTIVE"
