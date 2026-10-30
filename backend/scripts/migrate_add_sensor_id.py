"""
NETRA Cyber Threat Detection System - Database Migration Runner
Problem Statement PS 26145

Safely applies the sensor_id migration to PostgreSQL.
Verifies table counts before and after to ensure 100% data preservation.
Idempotent and safe to run multiple times.
"""

import os
import sys
import logging
from pathlib import Path

# Set up paths
backend_root = Path(__file__).resolve().parent.parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from dotenv import load_dotenv
env_path = backend_root / ".env"
root_env = backend_root.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
elif root_env.exists():
    load_dotenv(dotenv_path=root_env)
else:
    load_dotenv()

from src.database.database import engine
from sqlalchemy import text, inspect

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("migration")


MIGRATION_SQL = """
-- 1. Add sensor_id to flows table
ALTER TABLE flows ADD COLUMN IF NOT EXISTS sensor_id VARCHAR(64);

-- 2. Create index on flows(sensor_id)
CREATE INDEX IF NOT EXISTS ix_flows_sensor_id ON flows (sensor_id);

-- 3. Add sensor_id to alerts table
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensor_id VARCHAR(64);

-- 4. Create index on alerts(sensor_id)
CREATE INDEX IF NOT EXISTS ix_alerts_sensor_id ON alerts (sensor_id);
"""


def run_migration():
    if engine is None:
        logger.error("Database engine could not be initialized. Check DATABASE_URL.")
        sys.exit(1)

    # 1. Connection Safety Assertion: Verify host is local and database is cyber_threats
    db_host = engine.url.host
    db_name = engine.url.database
    db_port = engine.url.port or 5432
    logger.info(f"Target database: host='{db_host}', port={db_port}, database='{db_name}'")
    
    if db_host not in ("localhost", "127.0.0.1"):
        logger.error(f"ABORT: Migration target host is '{db_host}', expected local database ('localhost' or '127.0.0.1').")
        sys.exit(1)
        
    if db_name != "cyber_threats":
        logger.error(f"ABORT: Migration target database is '{db_name}', expected 'cyber_threats'.")
        sys.exit(1)

    logger.info("Connecting to database to verify pre-migration state...")
    with engine.connect() as conn:
        # Pre-migration row counts
        flows_before = conn.execute(text("SELECT count(*) FROM flows;")).scalar()
        alerts_before = conn.execute(text("SELECT count(*) FROM alerts;")).scalar()
        logger.info(f"Pre-migration row counts: flows={flows_before}, alerts={alerts_before}")

        # Check existing columns
        inspector = inspect(conn)
        flow_cols = [c["name"] for c in inspector.get_columns("flows")]
        alert_cols = [c["name"] for c in inspector.get_columns("alerts")]

        logger.info(f"'flows.sensor_id' present before: {'sensor_id' in flow_cols}")
        logger.info(f"'alerts.sensor_id' present before: {'sensor_id' in alert_cols}")

        logger.info("Executing migration SQL...")
        conn.commit()  # commit the pre-migration read transaction
        conn.execute(text("ALTER TABLE flows ADD COLUMN IF NOT EXISTS sensor_id VARCHAR(64);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_flows_sensor_id ON flows (sensor_id);"))
        conn.execute(text("ALTER TABLE alerts ADD COLUMN IF NOT EXISTS sensor_id VARCHAR(64);"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_alerts_sensor_id ON alerts (sensor_id);"))
        conn.commit()  # commit the DDL transaction

        # Post-migration row counts
        flows_after = conn.execute(text("SELECT count(*) FROM flows;")).scalar()
        alerts_after = conn.execute(text("SELECT count(*) FROM alerts;")).scalar()
        logger.info(f"Post-migration row counts: flows={flows_after}, alerts={alerts_after}")

        # Verify columns & indexes
        inspector_post = inspect(conn)
        flow_cols_post = [c["name"] for c in inspector_post.get_columns("flows")]
        alert_cols_post = [c["name"] for c in inspector_post.get_columns("alerts")]
        flow_idx_post = [idx["name"] for idx in inspector_post.get_indexes("flows")]
        alert_idx_post = [idx["name"] for idx in inspector_post.get_indexes("alerts")]

        assert "sensor_id" in flow_cols_post, "Migration failed: sensor_id not in flows table!"
        assert "sensor_id" in alert_cols_post, "Migration failed: sensor_id not in alerts table!"
        assert "ix_flows_sensor_id" in flow_idx_post, "Migration failed: ix_flows_sensor_id not found!"
        assert "ix_alerts_sensor_id" in alert_idx_post, "Migration failed: ix_alerts_sensor_id not found!"
        assert flows_before == flows_after, f"Data loss detected in flows! {flows_before} != {flows_after}"
        assert alerts_before == alerts_after, f"Data loss detected in alerts! {alerts_before} != {alerts_after}"

        logger.info("SUCCESS: Schema successfully updated. 100% of data preserved.")


if __name__ == "__main__":
    run_migration()
