"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.auth.sensor_auth

Authentication, authorization, cryptographic API key issuance, and rate limiting
for remote NETRA Windows Sensor devices transmitting telemetry.
Strictly verifies sensor identity without storing plaintext credentials.
"""

import os
import time
import hashlib
import secrets
import logging
import threading
from typing import Optional, Tuple, Dict, List
from collections import defaultdict

from fastapi import Request, Header, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.database.database import get_db
from src.database.models import SensorEnrollmentModel
from src.database.repository import SensorEnrollmentRepository

logger = logging.getLogger(__name__)

# Server-side salt for hashing sensor API keys (configured via env or fallback)
SENSOR_KEY_SALT = os.getenv("SENSOR_API_KEY_SALT", "netra_sensor_salt_ps26145_secure")

# Rate limit defaults: requests allowed per sensor per window (60 seconds)
DEFAULT_INGEST_RATE_LIMIT = int(os.getenv("SENSOR_INGEST_RATE_LIMIT_PER_MINUTE", "60"))
RATE_LIMIT_WINDOW_SECONDS = 60.0


def hash_sensor_api_key(api_key: str) -> str:
    """
    Produce a cryptographically secure SHA-256 hash of a sensor API key
    combined with the server-side salt.
    """
    salted = f"{SENSOR_KEY_SALT}:{api_key.strip()}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()


def generate_sensor_api_key() -> Tuple[str, str, str]:
    """
    Generate a cryptographically random, revocable sensor credential.
    Returns:
        (raw_api_key, api_key_hash, api_key_prefix)
    The raw_api_key is returned to the operator exactly once upon enrollment.
    """
    random_token = secrets.token_urlsafe(32)
    raw_api_key = f"netra_live_{random_token}"
    key_hash = hash_sensor_api_key(raw_api_key)
    key_prefix = f"{raw_api_key[:12]}..."
    return raw_api_key, key_hash, key_prefix


class SensorRateLimiter:
    """
    Thread-safe sliding-window rate limiter per authenticated sensor.
    Enforces request rate limits to protect cloud ingestion endpoints
    from volumetric flooding or misconfigured sensors.
    """
    def __init__(self, limit: int = DEFAULT_INGEST_RATE_LIMIT, window: float = RATE_LIMIT_WINDOW_SECONDS):
        self.limit = limit
        self.window = window
        self._history: Dict[str, List[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def is_allowed(self, sensor_id: str) -> Tuple[bool, int]:
        """
        Check if request is permitted under rate limit.
        Returns: (is_allowed: bool, retry_after_seconds: int)
        """
        now = time.time()
        with self._lock:
            timestamps = self._history[sensor_id]
            # Prune timestamps older than window
            cutoff = now - self.window
            self._history[sensor_id] = [t for t in timestamps if t > cutoff]
            current_count = len(self._history[sensor_id])

            if current_count >= self.limit:
                oldest = self._history[sensor_id][0]
                retry_after = max(1, int(oldest + self.window - now))
                return False, retry_after

            self._history[sensor_id].append(now)
            return True, 0

    def reset(self, sensor_id: Optional[str] = None):
        """Reset rate limit history for a specific sensor or all sensors."""
        with self._lock:
            if sensor_id:
                self._history.pop(sensor_id, None)
            else:
                self._history.clear()


# Global in-memory rate limiter instance
sensor_rate_limiter = SensorRateLimiter()


def extract_sensor_key(
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    authorization: Optional[str] = Header(None)
) -> Optional[str]:
    """
    Extract sensor credential from either 'X-Sensor-Key' header or
    'Authorization: Bearer <key>' header.
    """
    if x_sensor_key and x_sensor_key.strip():
        return x_sensor_key.strip()

    if authorization and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()

    return None


def get_authenticated_sensor(
    request: Request,
    x_sensor_key: Optional[str] = Header(None, alias="X-Sensor-Key"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> SensorEnrollmentModel:
    """
    FastAPI dependency to authenticate and authorize a remote sensor.
    Validates credential presence, verifies SHA-256 hash against database,
    checks active enrollment status, and enforces per-sensor rate limits.
    """
    raw_key = extract_sensor_key(x_sensor_key, authorization)
    if not raw_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing sensor authentication credential. Provide X-Sensor-Key header."
        )

    # Compute hash of supplied key
    key_hash = hash_sensor_api_key(raw_key)

    # Query sensor by credential hash
    sensor = SensorEnrollmentRepository.get_by_api_key_hash(db, key_hash)
    if not sensor:
        logger.warning("Rejected remote ingestion attempt: invalid sensor credential")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid sensor authentication credential."
        )

    # Verify sensor is not revoked
    if sensor.status != "ACTIVE":
        logger.warning(f"Rejected remote ingestion attempt for revoked sensor: {sensor.sensor_id}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Sensor credential has been revoked by an administrator."
        )

    # Check per-sensor rate limit
    allowed, retry_after = sensor_rate_limiter.is_allowed(sensor.sensor_id)
    if not allowed:
        logger.warning(f"Rate limit exceeded for sensor {sensor.sensor_id}. Retry-After: {retry_after}s")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for sensor. Maximum {sensor_rate_limiter.limit} requests per minute.",
            headers={"Retry-After": str(retry_after)}
        )

    return sensor
