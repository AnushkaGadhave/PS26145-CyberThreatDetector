"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.auth.security

Cryptographic password hashing via Argon2id, timing-safe verification,
password policy validation, and signed JWT session token generation.
"""

import os
import re
import secrets
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple, Dict, Any

import jwt
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

logger = logging.getLogger(__name__)

# Security & Session Configuration loaded from environment
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "netra-unidirectional-threat-detection-secret-key-26145")
JWT_ALGORITHM = "HS256"

# Default session duration: 8 hours (480 minutes)
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "480"))

# Cookie settings
SESSION_COOKIE_NAME = "netra_session"
# In development on http://127.0.0.1 or http://localhost, Secure must be False so browsers store the cookie over HTTP.
# In production with TLS/HTTPS, set SESSION_COOKIE_SECURE=true.
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "lax").lower()

# Rate limiting / brute-force lockout thresholds
MAX_FAILED_LOGIN_ATTEMPTS = int(os.getenv("MAX_FAILED_LOGIN_ATTEMPTS", "5"))
LOCKOUT_DURATION_MINUTES = int(os.getenv("LOCKOUT_DURATION_MINUTES", "15"))

# Initialize Argon2id password hasher with OWASP recommended parameters
# memory_cost=65536 (64 MiB), time_cost=3 iterations, parallelism=4 lanes
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    type=Type.ID
)

# Pre-computed dummy hash to run on non-existent email login attempts
# Guarantees constant time execution to neutralize timing-attack username enumeration
_DUMMY_HASH = _hasher.hash("dummy_mitigation_password_for_timing_safety_26145")


def hash_password(plain_password: str) -> str:
    """
    Hash a plaintext password using salted Argon2id.
    Never logs or persists the plaintext password.
    """
    if not plain_password:
        raise ValueError("Password cannot be empty.")
    return _hasher.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash in constant time.
    Returns True if valid, False otherwise.
    """
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def dummy_verify_password() -> None:
    """
    Performs a dummy password verification against a fixed hash.
    Used when an authentication attempt is made for a non-existent email
    so that response time is indistinguishable from a valid email attempt.
    """
    try:
        _hasher.verify(_DUMMY_HASH, "dummy_mismatch")
    except Exception:
        pass


def validate_password_strength(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates that a password satisfies defense-grade SOC security policies:
    - At least 10 characters in length
    - At least one uppercase letter (A-Z)
    - At least one lowercase letter (a-z)
    - At least one numerical digit (0-9)
    - At least one special symbol (!@#$%^&*...)
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit (0-9)."
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;`~]', password):
        return False, "Password must contain at least one special character (!@#$%^&*...)."
    return True, None


def create_access_token(
    user_id: str,
    email: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> Tuple[str, str, datetime]:
    """
    Mint a cryptographically signed JWT session token with a unique jti identifier.
    Returns:
        (encoded_token, token_jti, expires_at_datetime)
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    token_jti = secrets.token_hex(16)

    payload: Dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "role": role,
        "jti": token_jti,
        "iat": now,
        "exp": expire,
    }

    encoded_jwt = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt, token_jti, expire


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodes and validates a JWT session token.
    Verifies signature and expiration timestamp.
    Returns decoded payload dictionary, or None if invalid or expired.
    """
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        logger.debug("JWT token has expired.")
        return None
    except jwt.InvalidTokenError as e:
        logger.debug(f"Invalid JWT token: {e}")
        return None
    except Exception as e:
        logger.warning(f"Unexpected error decoding token: {e}")
        return None
