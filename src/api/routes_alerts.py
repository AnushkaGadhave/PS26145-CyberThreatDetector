"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_alerts

FastAPI router for threat alert retrieval, recent alert streaming, and threat summaries.
Read-only: does not modify alert state or perform active network mitigation.
"""

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.schemas import AlertResponse, AlertListResponse, AlertSummaryResponse
from src.database.repository import AlertRepository, DashboardRepository

router = APIRouter(prefix="/api/alerts", tags=["Threat Alerts"])


@router.get(
    "",
    response_model=AlertListResponse,
    summary="Get Paginated Threat Alerts",
    description="Retrieve paginated threat alerts ordered newest first, with optional severity, threat class, and time filtering."
)
def get_alerts(
    limit: int = Query(50, ge=1, le=1000, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    severity: Optional[str] = Query(None, description="Filter by severity (e.g. CRITICAL, HIGH, MEDIUM, LOW, BENIGN)"),
    threat_class: Optional[str] = Query(None, description="Filter by threat class (e.g. DDoS, BOTNET_C2, RECON_PORTSCAN, MULTI_THREAT)"),
    detector: Optional[str] = Query(None, description="Filter by detector name substring"),
    traffic_context: Optional[str] = Query(None, description="Filter by traffic context (e.g. UNLABELED_LIVE, LAB_ATTACK)"),
    start_time: Optional[float] = Query(None, description="Filter alerts on or after this timestamp"),
    end_time: Optional[float] = Query(None, description="Filter alerts on or before this timestamp"),
    db: Session = Depends(get_db)
):
    try:
        if start_time is not None and end_time is not None and start_time > end_time:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="start_time cannot be greater than end_time."
            )

        alerts, total = AlertRepository.get_alerts(
            db=db,
            limit=limit,
            offset=offset,
            severity=severity,
            threat_class=threat_class,
            detector=detector,
            traffic_context=traffic_context,
            start_time=start_time,
            end_time=end_time
        )
        return AlertListResponse(
            total=total,
            limit=limit,
            offset=offset,
            alerts=[a.to_dict() for a in alerts]
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )


@router.get(
    "/recent",
    response_model=List[AlertResponse],
    summary="Get Recent Alerts for Live Polling",
    description="Retrieve the latest 20 threat alerts ordered by timestamp descending for live dashboard stream polling."
)
def get_recent_alerts(
    limit: int = Query(20, ge=1, le=100, description="Number of recent alerts to retrieve"),
    db: Session = Depends(get_db)
):
    try:
        alerts = AlertRepository.get_recent_alerts(db=db, limit=limit)
        return [a.to_dict() for a in alerts]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )


@router.get(
    "/summary",
    response_model=AlertSummaryResponse,
    summary="Get Alert Summary Statistics",
    description="Retrieve aggregated alert counts by severity, threat class, and unlabeled live status for dashboard telemetry."
)
def get_alert_summary(
    db: Session = Depends(get_db)
):
    try:
        summary_data = DashboardRepository.get_alert_summary(db=db)
        return AlertSummaryResponse(**summary_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )


@router.get(
    "/{alert_id}",
    response_model=AlertResponse,
    summary="Get Alert By ID",
    description="Retrieve a single threat alert by its unique alert_id, including full evidence and explanation."
)
def get_alert_by_id(
    alert_id: str,
    db: Session = Depends(get_db)
):
    try:
        alert = AlertRepository.get_by_alert_id(db=db, alert_id=alert_id)
        if not alert:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Alert '{alert_id}' not found."
            )
        return alert.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )
