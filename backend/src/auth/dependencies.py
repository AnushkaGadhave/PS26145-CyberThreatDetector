"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.auth.dependencies

FastAPI security dependencies for verifying authenticated sessions, extracting
the current user identity, and enforcing role-based access control (RBAC).
"""

import logging
from typing import Optional
from fastapi import Request, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import UserModel
from src.database.repository import UserRepository, UserSessionRepository
from src.auth.security import (
    SESSION_COOKIE_NAME,
    decode_access_token,
)

logger = logging.getLogger(__name__)


def extract_token_from_request(request: Request) -> Optional[str]:
    """
    Extract session token from HttpOnly cookie first.
    Falls back to 'Authorization: Bearer <token>' header for API clients / tests.
    """
    # 1. Primary: HttpOnly session cookie
    cookie_token = request.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    # 2. Secondary fallback: Bearer Authorization header
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        return auth_header[7:].strip()

    return None


async def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> UserModel:
    """
    FastAPI dependency validating the caller's authentication.
    Verifies token validity, server-side revocation status, and user account active state.
    Raises 401 Unauthorized if unauthenticated, expired, or revoked.
    """
    token = extract_token_from_request(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in to access security console.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user_id = payload.get("sub")
    jti = payload.get("jti")

    if not user_id or not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Malformed session token.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    # Check server-side session revocation status
    if UserSessionRepository.is_jti_revoked(db, jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been terminated. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    user = UserRepository.get_by_id(db, user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account has been disabled. Contact SOC administrator."
        )

    return user


async def require_admin(
    current_user: UserModel = Depends(get_current_user)
) -> UserModel:
    """
    Enforces Administrator role authorization.
    Required for sensor control actions (starting and stopping packet capture).
    """
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrative privileges required to perform this action."
        )
    return current_user


async def require_analyst_or_admin(
    current_user: UserModel = Depends(get_current_user)
) -> UserModel:
    """
    Enforces Analyst or Administrator role authorization.
    """
    if current_user.role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient operational permissions."
        )
    return current_user
