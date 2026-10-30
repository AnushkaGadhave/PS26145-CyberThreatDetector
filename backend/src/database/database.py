"""
ThreatTrack — AI-Powered Network Threat Monitoring System
Module: src.database.database

SQLAlchemy database session and engine initialization.
Loads DATABASE_URL securely from environment variables.
Handles connection degradation cleanly without crashing the API process.
Prepares connection pooling and SSL enforcement for future Supabase cloud databases.
"""

import os
import re
import logging
import urllib.parse
from pathlib import Path
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.engine.url import make_url, URL
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


def build_safe_database_url(raw_url: str) -> tuple[str, str]:
    """
    Normalizes DATABASE_URL:
    1. Ensures PostgreSQL URLs use the psycopg2 driver (postgresql+psycopg2://).
    2. Safely URL-encodes passwords with special characters (@, #, %, etc.) by locating the authority boundary.
    3. Enforces sslmode=require for remote cloud connections (e.g. Supabase) without duplication.
    4. Preserves SQLite in-memory or file URLs for unit tests.
    Returns (final_connection_url, masked_safe_url_for_logging).
    """
    if not raw_url:
        raw_url = "postgresql://postgres:root@localhost:5432/cyber_threats"

    # Support SQLite test URLs unmodified
    if raw_url.startswith("sqlite"):
        return raw_url, raw_url

    # Normalize driver prefix
    url_to_parse = raw_url
    if url_to_parse.startswith("postgresql://"):
        url_to_parse = url_to_parse.replace("postgresql://", "postgresql+psycopg2://", 1)
    elif url_to_parse.startswith("postgres://"):
        url_to_parse = url_to_parse.replace("postgres://", "postgresql+psycopg2://", 1)

    # Decompose into components by locating the rightmost '@' before the database path
    # Scheme: driver://user:password@host:port/database?query
    try:
        if "://" in url_to_parse and "@" in url_to_parse:
            driver_prefix, rest = url_to_parse.split("://", 1)
            if "/" in rest:
                authority, path_query = rest.split("/", 1)
            else:
                authority, path_query = rest, ""

            last_at = authority.rfind("@")
            if last_at != -1:
                userinfo = authority[:last_at]
                host_port = authority[last_at + 1:]

                first_colon = userinfo.find(":")
                user = userinfo[:first_colon] if first_colon != -1 else userinfo
                raw_password = userinfo[first_colon + 1:] if first_colon != -1 else ""
                raw_password = urllib.parse.unquote_plus(raw_password)

                if ":" in host_port:
                    host, port_str = host_port.split(":", 1)
                    port = int(port_str) if port_str.isdigit() else 5432
                else:
                    host, port = host_port, 5432

                if "?" in path_query:
                    db_name, query_str = path_query.split("?", 1)
                else:
                    db_name, query_str = path_query, ""

                query_params = urllib.parse.parse_qs(query_str)
                flat_query = {k: v[0] for k, v in query_params.items()}

                is_local = host in ("localhost", "127.0.0.1", "::1", "")
                if not is_local and "sslmode" not in flat_query:
                    flat_query["sslmode"] = "require"

                url_obj = URL.create(
                    drivername=driver_prefix,
                    username=user,
                    password=raw_password,
                    host=host,
                    port=port,
                    database=db_name,
                    query=flat_query
                )
                return (
                    url_obj.render_as_string(hide_password=False),
                    url_obj.render_as_string(hide_password=True),
                )
    except Exception as e:
        logger.warning(f"URL component normalization fallback: {e}")

    # Fallback to standard make_url
    try:
        parsed = make_url(url_to_parse)
        is_local = parsed.host in ("localhost", "127.0.0.1", "::1", None)
        query = dict(parsed.query)
        if not is_local and "sslmode" not in query:
            query["sslmode"] = "require"

        final_url_obj = parsed.set(query=query)
        return (
            final_url_obj.render_as_string(hide_password=False),
            final_url_obj.render_as_string(hide_password=True),
        )
    except Exception:
        return url_to_parse, "postgresql+psycopg2://***@***"


# Database Connection URL Resolution (Supports both DATABASE_URL and SUPABASE_DATABASE_URL)
raw_db_url = os.getenv("DATABASE_URL") or os.getenv("SUPABASE_DATABASE_URL") or "postgresql://postgres:root@localhost:5432/cyber_threats"
DATABASE_URL, MASKED_DATABASE_URL = build_safe_database_url(raw_db_url)

# Base declarative class for SQLAlchemy models
Base = declarative_base()

# SQLAlchemy Engine Configuration
# Configured conservatively for Supabase Shared Pooler (Session Mode) & local PostgreSQL:
# - pool_size: 5
# - max_overflow: 5
# - pool_pre_ping: True (checks connection liveness before issuing queries)
# - pool_recycle: 300 (safely recycles idle connections every 5 minutes to prevent stale PgBouncer drops)
try:
    is_sqlite = DATABASE_URL.startswith("sqlite")
    engine_kwargs = {
        "pool_pre_ping": True,
    }
    if not is_sqlite:
        engine_kwargs.update({
            "pool_size": 5,
            "max_overflow": 5,
            "pool_recycle": 300,
            "connect_args": {"connect_timeout": 10},
        })

    engine = create_engine(DATABASE_URL, **engine_kwargs)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info(f"SQLAlchemy engine created successfully for: {MASKED_DATABASE_URL}")
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
        from src.database.models import (  # noqa: F401
            FlowModel,
            AlertModel,
            ModelStatusModel,
            UserModel,
            UserSessionModel,
            SensorEnrollmentModel,
            SensorIngestRecordModel,
        )
        Base.metadata.create_all(bind=engine)
        logger.info("All database tables created or verified.")
        return True
    except Exception as e:
        logger.error(f"Error during database table creation: {e}")
        return False
