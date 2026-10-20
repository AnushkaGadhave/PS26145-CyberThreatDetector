"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.routes_auth

FastAPI authentication endpoints:
- POST /api/auth/login: Authenticates operator credentials, sets HttpOnly session cookie
- POST /api/auth/logout: Revokes server session and clears authentication cookies
- GET /api/auth/me: Returns currently authenticated user identity and role
"""

import math
import logging
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Request, Response, HTTPException, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import UserModel
from src.database.repository import UserRepository, UserSessionRepository
from src.database.schemas import (
    LoginRequest,
    LoginResponse,
    UserResponse,
    CurrentUserResponse,
    LogoutResponse,
)
from src.auth.security import (
    verify_password,
    dummy_verify_password,
    create_access_token,
    decode_access_token,
    SESSION_COOKIE_NAME,
    SESSION_COOKIE_SECURE,
    SESSION_COOKIE_SAMESITE,
    ACCESS_TOKEN_EXPIRE_MINUTES,
    MAX_FAILED_LOGIN_ATTEMPTS,
    LOCKOUT_DURATION_MINUTES,
)
from src.auth.dependencies import get_current_user, extract_token_from_request

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication & Access Control"])


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Operator Sign In",
    description=(
        "Authenticates SOC credentials via email and password. "
        "Upon successful authentication, establishes a secure HttpOnly session cookie. "
        "Enforces brute-force lockout and timing-safe verification."
    )
)
def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and mint session cookie.
    Generic error returned for any invalid credential combination.
    """
    normalized_email = payload.email.strip().lower()
    user = UserRepository.get_by_email(db, normalized_email)

    now = datetime.now(timezone.utc)

    # 1. Check account lockout status if user exists
    if user and user.locked_until:
        # Ensure timezone-aware comparison
        locked_until_utc = user.locked_until
        if locked_until_utc.tzinfo is None:
            locked_until_utc = locked_until_utc.replace(tzinfo=timezone.utc)

        if locked_until_utc > now:
            remaining_seconds = (locked_until_utc - now).total_seconds()
            remaining_minutes = max(1, math.ceil(remaining_seconds / 60))
            logger.warning(f"Login attempt on locked account: {normalized_email}")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account temporarily locked due to repeated failed login attempts. Please try again in {remaining_minutes} minute(s)."
            )
        else:
            # Lockout expired, reset counter
            user.locked_until = None
            user.failed_login_attempts = 0
            db.commit()

    # 2. Verify password
    if user:
        is_valid = verify_password(payload.password, user.hashed_password)
    else:
        # Run dummy verification to eliminate timing-channel username discovery
        dummy_verify_password()
        is_valid = False

    # 3. Handle invalid credentials
    if not user or not is_valid:
        if user:
            UserRepository.record_login_failure(
                db, user,
                max_attempts=MAX_FAILED_LOGIN_ATTEMPTS,
                lockout_minutes=LOCKOUT_DURATION_MINUTES
            )
            logger.warning(
                f"Failed login attempt for {normalized_email} (Attempt {user.failed_login_attempts}/{MAX_FAILED_LOGIN_ATTEMPTS})"
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password. Please verify your credentials."
        )

    # 4. Check active account status
    if not user.is_active:
        logger.warning(f"Login attempt on inactive account: {normalized_email}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive or disabled. Contact SOC administrator."
        )

    # 5. Success: Reset failure count and update last_login_at
    UserRepository.record_login_success(db, user)

    # 6. Mint JWT and register session record
    token, jti, expires_at = create_access_token(
        user_id=user.user_id,
        email=user.email,
        role=user.role
    )

    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("User-Agent")

    UserSessionRepository.create_session(
        db=db,
        user_id=user.user_id,
        token_jti=jti,
        expires_at=expires_at,
        ip_address=client_ip,
        user_agent=user_agent
    )

    # 7. Set secure HttpOnly session cookie
    max_age_seconds = ACCESS_TOKEN_EXPIRE_MINUTES * 60
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
        secure=SESSION_COOKIE_SECURE,
        max_age=max_age_seconds,
        path="/",
    )

    logger.info(f"Operator authenticated successfully: {user.email} (Role: {user.role})")
    return LoginResponse(
        success=True,
        message="Authentication successful.",
        user=UserResponse.model_validate(user)
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Operator Sign Out",
    description="Revokes active session on the server and deletes the HttpOnly session cookie."
)
def logout(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """
    Invalidates current session and clears authentication cookies.
    """
    token = extract_token_from_request(request)
    if token:
        payload = decode_access_token(token)
        if payload and "jti" in payload:
            UserSessionRepository.revoke_session_by_jti(db, payload["jti"])
            logger.info(f"Revoked session jti={payload['jti']} for user={payload.get('sub')}")

    # Delete session cookie across browser
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        httponly=True,
        samesite=SESSION_COOKIE_SAMESITE,
        secure=SESSION_COOKIE_SECURE,
        path="/",
    )

    return LogoutResponse(
        success=True,
        message="Session terminated successfully."
    )


@router.get(
    "/me",
    response_model=CurrentUserResponse,
    summary="Get Current Authenticated User",
    description="Returns the profile and role of the currently signed-in operator."
)
def get_current_user_profile(
    current_user: UserModel = Depends(get_current_user)
):
    """
    Retrieve profile details for the authenticated caller.
    """
    return CurrentUserResponse(
        user=UserResponse.model_validate(current_user)
    )
