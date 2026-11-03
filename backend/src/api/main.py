"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.main

Main FastAPI backend application entry point.
Exposes read-only REST endpoints for network flow metadata, threat alerts,
model operational statuses, and aggregated dashboard analytics.
"""

import os
import sys
import re
import logging
from pathlib import Path
from contextlib import asynccontextmanager

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from dotenv import load_dotenv
env_path = project_root / ".env"
root_env_path = project_root.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
elif root_env_path.exists():
    load_dotenv(dotenv_path=root_env_path)
else:
    load_dotenv()

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

from src.database.database import init_db
from src.database.schemas import HealthResponse
from src.capture.capture_service import capture_manager
from src.api.routes_flows import router as flows_router
from src.api.routes_alerts import router as alerts_router
from src.api.routes_models import router as models_router
from src.api.routes_dashboard import router as dashboard_router
from src.api.routes_capture import router as capture_router
from src.api.routes_auth import router as auth_router
from src.api.routes_reports import router as reports_router
from src.api.routes_sensor import router as sensor_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s - %(message)s")
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager for startup and shutdown routines."""
    logger.info("Initializing PS 26145 Cyber Threat Detection API...")
    try:
        init_db()
        logger.info("Database schema initialized successfully.")
    except Exception as e:
        logger.warning(f"Database initialization warning on startup: {e}")
    yield
    logger.info("Shutting down PS 26145 Cyber Threat Detection API...")
    try:
        if capture_manager.status == "RUNNING":
            logger.info("Stopping active capture worker on shutdown...")
            capture_manager.stop()
    except Exception as e:
        logger.warning(f"Error stopping capture worker during shutdown: {e}")


app = FastAPI(
    title="PS 26145 Cyber Threat Detection API",
    description=(
        "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic.\n\n"
        "Provides read-only access to network flow statistics, machine-learning threat detection alerts, "
        "explainable feature evidence, and model compatibility statuses.\n\n"
        "**Safety Policy**: Strictly read-only monitoring. No active network mitigation, blocking, probing, "
        "or payload inspection is performed."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Configuration
# Supports explicit CORS_ORIGINS as well as Vercel preview URLs via CORS_ORIGIN_REGEX
# Normalizes origins by safely stripping surrounding quotes, whitespace, and trailing slashes.
raw_cors_origins = os.getenv(
    "CORS_ORIGINS",
    "https://threattrack.vercel.app,http://localhost:5174,http://127.0.0.1:5174,http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
)

origins: list[str] = []
for entry in raw_cors_origins.split(","):
    cleaned = entry.strip().strip("'\"").rstrip("/")
    if cleaned and cleaned not in origins:
        origins.append(cleaned)

# Always guarantee production Vercel frontend and local development origins are permitted
guaranteed_origins = [
    "https://threattrack.vercel.app",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
for origin in guaranteed_origins:
    if origin not in origins:
        origins.append(origin)

origin_regex = os.getenv("CORS_ORIGIN_REGEX", r"https://.*\.vercel\.app")
compiled_origin_regex = None
if origin_regex:
    try:
        compiled_origin_regex = re.compile(origin_regex)
    except Exception as e:
        logger.warning(f"Failed to compile CORS_ORIGIN_REGEX '{origin_regex}': {e}")
        compiled_origin_regex = re.compile(r"https://.*\.vercel\.app")

cors_kwargs = {
    "allow_origins": origins,
    "allow_credentials": True,
    "allow_methods": ["*"],
    "allow_headers": ["*"],
    "expose_headers": ["Content-Disposition"],
    "max_age": 86400,
}
if origin_regex:
    cors_kwargs["allow_origin_regex"] = origin_regex

app.add_middleware(CORSMiddleware, **cors_kwargs)


def get_cors_headers_for_request(request: Request) -> dict[str, str]:
    """Helper to compute CORS response headers for unhandled exception responses."""
    origin = request.headers.get("origin")
    if not origin:
        return {}
    normalized_origin = origin.strip().rstrip("/")
    is_allowed = (
        normalized_origin in origins
        or (compiled_origin_regex is not None and bool(compiled_origin_regex.fullmatch(normalized_origin)))
    )
    if is_allowed:
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Credentials": "true",
            "Access-Control-Expose-Headers": "Content-Disposition",
            "Vary": "Origin",
        }
    return {}


@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System Health"],
    summary="Service Health Check",
    description="Returns the operational status and service name of the Cyber Threat Detection API."
)
def health_check():
    """Health check endpoint returning service status."""
    return HealthResponse(status="ok", service="PS26145 API")


# Register API Routers
app.include_router(auth_router)
app.include_router(reports_router)
app.include_router(flows_router)
app.include_router(alerts_router)
app.include_router(models_router)
app.include_router(dashboard_router)
app.include_router(capture_router)
app.include_router(sensor_router)


# Global Exception Handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    cors_headers = get_cors_headers_for_request(request)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error occurred. Check server logs."},
        headers=cors_headers
    )


if __name__ == "__main__":
    import uvicorn
    # Supports hosting platform's PORT environment variable (e.g. Render)
    # Binds to 0.0.0.0 when PORT or API_HOST is configured, falling back to 127.0.0.1 for local testing
    default_host = "0.0.0.0" if os.getenv("PORT") else "127.0.0.1"
    host = os.getenv("API_HOST", default_host)
    port = int(os.getenv("PORT", os.getenv("API_PORT", "8000")))
    uvicorn.run("src.api.main:app", host=host, port=port, proxy_headers=True)
