"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.api.main

Main FastAPI backend application entry point.
Exposes read-only REST endpoints for network flow metadata, threat alerts,
model operational statuses, and aggregated dashboard analytics.
"""

import os
import sys
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
# Restricts cross-origin requests to configured local frontend URLs
raw_cors_origins = os.getenv(
    "CORS_ORIGINS",
    "http://localhost:5174,http://127.0.0.1:5174,http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000"
)
origins = [o.strip() for o in raw_cors_origins.split(",") if o.strip()]

# Explicitly ensure exact local development origins are permitted (including Vite port 5174)
for dev_origin in ["http://localhost:5174", "http://127.0.0.1:5174"]:
    if dev_origin not in origins:
        origins.append(dev_origin)

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],  # Support Read-Only GET, Administrative POST, and Preflight OPTIONS
    allow_headers=["*"],
    expose_headers=["Content-Disposition"],
)


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


# Global Exception Handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "Internal server error occurred. Check server logs."}
    )
