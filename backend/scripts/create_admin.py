"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: scripts.create_admin

Administrative bootstrap utility for initializing or updating SOC administrator accounts.
No public registration exists; this script is the controlled method for provisioning administrators.

Usage (Interactive):
    python scripts/create_admin.py

Usage (Non-interactive / Automation):
    python scripts/create_admin.py --email admin@soc.gov.in --name "SOC Lead Administrator" --password "StrongPassword123!" [--force]
"""

import sys
import os
import re
import getpass
import argparse
from pathlib import Path

# Ensure project root is in sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from dotenv import load_dotenv
env_path = backend_dir / ".env"
root_env_path = backend_dir.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)
elif root_env_path.exists():
    load_dotenv(dotenv_path=root_env_path)
else:
    load_dotenv()

from src.database.database import SessionLocal, init_db
from src.database.repository import UserRepository
from src.auth.security import hash_password, validate_password_strength


def validate_email_format(email: str) -> bool:
    """Validate RFC 5322 compliant email format."""
    email_regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(email_regex, email.strip()))


def create_or_update_admin(email: str, name: str, password: str, force: bool = False) -> bool:
    """
    Validates, hashes, and provisions an administrator account in the database.
    Never prints or logs the plaintext password.
    """
    # 1. Validate email format
    email = email.strip().lower()
    if not validate_email_format(email):
        print(f"[ERROR] Invalid email address format: '{email}'")
        return False

    # 2. Validate name
    name = name.strip()
    if not name:
        print("[ERROR] Administrator full name cannot be blank.")
        return False

    # 3. Validate password policy
    is_valid, err_msg = validate_password_strength(password)
    if not is_valid:
        print(f"[ERROR] Password policy violation: {err_msg}")
        return False

    # 4. Initialize database schema
    init_db()

    if SessionLocal is None:
        print("[ERROR] Database session factory unavailable. Check DATABASE_URL.")
        return False

    db = SessionLocal()
    try:
        existing_user = UserRepository.get_by_email(db, email)

        if existing_user:
            if not force:
                print(f"[WARNING] Account '{email}' already exists (Role: {existing_user.role}).")
                print("Refusing to overwrite without explicit administrative confirmation.")
                print("To update the existing account, supply the '--force' flag or confirm overwrite.")
                return False

            # Force update existing account
            print(f"[INFO] Overwriting existing credentials for administrator: '{email}'...")
            hashed = hash_password(password)
            existing_user.hashed_password = hashed
            existing_user.full_name = name
            existing_user.role = "admin"
            existing_user.is_active = True
            existing_user.failed_login_attempts = 0
            existing_user.locked_until = None
            db.commit()
            db.refresh(existing_user)
            print("======================================================================")
            print(f"[SUCCESS] Administrator credentials updated successfully!")
            print(f"User ID:   {existing_user.user_id}")
            print(f"Email:     {existing_user.email}")
            print(f"Full Name: {existing_user.full_name}")
            print(f"Role:      {existing_user.role}")
            print("======================================================================")
            return True

        # Check total existing admins
        existing_admins_count = UserRepository.count_admins(db)
        if existing_admins_count > 0 and not force:
            print(f"[NOTICE] The system already has {existing_admins_count} active administrator(s).")

        # Hash with Argon2id and create account
        hashed = hash_password(password)
        new_admin = UserRepository.create_user(
            db=db,
            email=email,
            hashed_password=hashed,
            full_name=name,
            role="admin",
            is_active=True
        )

        print("======================================================================")
        print(f"[SUCCESS] Administrator account provisioned successfully!")
        print(f"User ID:   {new_admin.user_id}")
        print(f"Email:     {new_admin.email}")
        print(f"Full Name: {new_admin.full_name}")
        print(f"Role:      {new_admin.role}")
        print("======================================================================")
        return True

    except Exception as e:
        print(f"[ERROR] Database error during administrator provisioning: {e}")
        db.rollback()
        return False
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="NETRA Administrator Account Bootstrap Tool (SIH PS 26145)"
    )
    parser.add_argument("--email", help="Administrator work email (e.g. admin@soc.gov.in)")
    parser.add_argument("--name", help="Administrator full name (e.g. SOC Lead)")
    parser.add_argument("--password", help="Administrator password (optional, prompted if omitted)")
    parser.add_argument("--force", action="store_true", help="Force overwrite if account already exists")

    args = parser.parse_args()

    print("======================================================================")
    print("   NETRA SENSOR — ADMINISTRATOR PROVISIONING TOOL (SIH PS 26145)")
    print("======================================================================")

    # 1. Determine Email
    email = args.email
    if not email:
        email = input("Enter administrator work email (e.g. admin@soc.gov.in): ").strip()

    # 2. Determine Full Name
    name = args.name
    if not name:
        name = input("Enter administrator full name (e.g. Lead SOC Officer): ").strip()

    # 3. Determine Password securely
    password = args.password
    if not password:
        password = getpass.getpass("Enter administrator password: ")
        confirm_password = getpass.getpass("Confirm administrator password: ")
        if password != confirm_password:
            print("[ERROR] Passwords do not match.")
            sys.exit(1)

    success = create_or_update_admin(email, name, password, force=args.force)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
