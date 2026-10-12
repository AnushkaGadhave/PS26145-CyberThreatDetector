"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_dashboard

FastAPI router for serving aggregated telemetry overviews, time-window alert volumes,
top talking host statistics, and protocol breakdowns for dashboard interfaces.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.schemas import DashboardOverviewResponse
from src.database.repository import DashboardRepository

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get(
    "/overview",
    response_model=DashboardOverviewResponse,
    summary="Get Dashboard Telemetry Overview",
    description="Retrieve a complete snapshot of network flow totals, alert velocity, severity distributions, top communicators, and model health."
)
def get_dashboard_overview(
    db: Session = Depends(get_db)
):
    try:
        overview_data = DashboardRepository.get_overview(db=db)
        return DashboardOverviewResponse(**overview_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )
