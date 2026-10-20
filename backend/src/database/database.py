"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.database.database

SQLAlchemy database session and engine initialization.
Loads DATABASE_URL securely from environment variables.
Handles connection degradation cleanly without crashing the API process.
"""

import os
import logging
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

logger = logging.getLogger(__name__)

# Load environment variables from .env file
backend_root = Path(__file__).resolve().parent.parent.parent
env_path = backend_root / ".env"
root_env_path = backend_root.parent / ".env"

if env_path.exists():
    load_dotenv(dotenv_path=env_path)
elif root_env_path.exists():
    load_dotenv(dotenv_path=root_env_path)
else:
    load_dotenv()

# Database Connection URL
raw_db_url = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:root@localhost:5432/cyber_threats"
)
# Ensure SQLAlchemy uses psycopg2 driver if generic postgresql:// prefix is given
if raw_db_url.startswith("postgresql://"):
    DATABASE_URL = raw_db_url.replace("postgresql://", "postgresql+psycopg2://", 1)
else:
    DATABASE_URL = raw_db_url

# Base declarative class for SQLAlchemy models
Base = declarative_base()

# SQLAlchemy Engine Configuration
# pool_pre_ping checks connection health before issuing queries
try:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
        pool_recycle=1800,
        connect_args={"connect_timeout": 5} if "postgresql" in DATABASE_URL else {}
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("SQLAlchemy engine created successfully.")
except Exception as e:
    logger.error(f"Failed to create SQLAlchemy engine: {e}")
    engine = None
    SessionLocal = None


def get_db():
    """
    FastAPI dependency for obtaining a database session per request.
    Yields session and guarantees cleanup / closing.
    """
    if SessionLocal is None:
        raise RuntimeError("Database session factory is not available. Check DATABASE_URL configuration.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """
    Initializes database schema and creates all tables and indexes.
    Returns True on success, False on connection failure.
    """
    if engine is None:
        logger.error("Cannot initialize database: SQLAlchemy engine is None.")
        return False
    try:
        from src.database.models import FlowModel, AlertModel, ModelStatusModel, UserModel, UserSessionModel  # noqa: F401
        Base.metadata.create_all(bind=engine)
        logger.info("All database tables created or verified.")
        return True
    except Exception as e:
        logger.error(f"Error during database table creation: {e}")
        return False
