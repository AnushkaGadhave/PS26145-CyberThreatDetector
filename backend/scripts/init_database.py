"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Script: scripts/init_database.py

Initializes the PostgreSQL database schema and creates all required tables and indexes.
"""

import os
import sys
from pathlib import Path

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent
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

from src.database.database import engine, init_db
from sqlalchemy import text


def main():
    if engine is None:
        print("========================================")
        print("DATABASE INITIALIZATION")
        print("========================================")
        print("Connection:")
        print("FAILED - SQLAlchemy engine could not be created. Check DATABASE_URL.")
        print("========================================")
        sys.exit(1)

    try:
        # Test basic connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1;"))
            
        success = init_db()
        if not success:
            raise RuntimeError("init_db returned False")

        print("========================================")
        print("DATABASE INITIALIZATION")
        print("========================================")
        print("Connection:")
        print("SUCCESS")
        print("")
        print("Tables:")
        print("flows")
        print("alerts")
        print("model_status")
        print("")
        print("Indexes:")
        print("CREATED")
        print("========================================")
    except Exception as e:
        print("========================================")
        print("DATABASE INITIALIZATION")
        print("========================================")
        print("Connection:")
        print(f"FAILED - Error: {e}")
        print("========================================")
        sys.exit(1)


if __name__ == "__main__":
    main()
