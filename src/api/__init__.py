"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api

FastAPI backend exposing read-only RESTful security telemetry, flow statistics,
threat alerts, model compatibility statuses, and dashboard metrics.
"""

from src.api.main import app

__all__ = ["app"]
