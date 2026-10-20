"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_models

FastAPI router for inspecting threat model operational and feature compatibility statuses.
Provides transparent disclosures regarding prototype limitations and training baselines.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.schemas import ModelStatusResponse
from src.database.repository import ModelStatusRepository
from src.auth.dependencies import get_current_user

router = APIRouter(
    prefix="/api/models",
    tags=["Model Status"],
    dependencies=[Depends(get_current_user)]
)


@router.get(
    "/status",
    response_model=List[ModelStatusResponse],
    summary="Get Model Operational & Compatibility Statuses",
    description="Retrieve operational status, runtime feature compatibility, and known limitations for all trained threat detectors."
)
def get_model_statuses(
    db: Session = Depends(get_db)
):
    try:
        models = ModelStatusRepository.get_all(db=db)
        return [m.to_dict() for m in models]
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database query error: {str(e)}"
        )
