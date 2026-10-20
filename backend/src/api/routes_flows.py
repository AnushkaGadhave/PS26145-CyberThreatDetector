"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_flows

FastAPI router for network flow metadata querying and pagination.
Read-only: does not modify or capture network traffic.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.schemas import FlowResponse, FlowListResponse
from src.database.repository import FlowRepository
from src.auth.dependencies import get_current_user

router = APIRouter(
    prefix="/api/flows",
    tags=["Flows"],
    dependencies=[Depends(get_current_user)]
)


@router.get(
    "",
    response_model=FlowListResponse,
    summary="Get Paginated Network Flows",
    description="Retrieve paginated network flow records with optional filtering by protocol, IPs, and context."
)
def get_flows(
    limit: int = Query(50, ge=1, le=1000, description="Maximum records to return"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
    protocol: Optional[str] = Query(None, description="Filter by protocol (e.g. TCP, UDP, ICMP)"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    dst_ip: Optional[str] = Query(None, description="Filter by destination IP address"),
    traffic_context: Optional[str] = Query(None, description="Filter by traffic context (e.g. UNLABELED_LIVE, LAB_ATTACK)"),
    db: Session = Depends(get_db)
):
    try:
        flows, total = FlowRepository.get_flows(
            db=db,
            limit=limit,
            offset=offset,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            traffic_context=traffic_context
        )
        return FlowListResponse(
            total=total,
            limit=limit,
            offset=offset,
            flows=[f.to_dict() for f in flows]
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )


@router.get(
    "/{flow_id}",
    response_model=FlowResponse,
    summary="Get Flow By ID",
    description="Retrieve a single network flow record by its unique flow_id."
)
def get_flow_by_id(
    flow_id: str,
    db: Session = Depends(get_db)
):
    try:
        flow = FlowRepository.get_by_flow_id(db=db, flow_id=flow_id)
        if not flow:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Flow '{flow_id}' not found."
            )
        return flow.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )
