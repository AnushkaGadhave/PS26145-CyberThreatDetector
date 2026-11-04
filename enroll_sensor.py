#!/usr/bin/env python3
"""
ThreatTrack - Automatic Sensor Enrollment Utility
Problem Statement PS 26145: AI-Based Threat Detection in Unidirectional IP Traffic

Redeems a single-use enrollment token from the ThreatTrack dashboard, receives
cryptographic sensor credentials, and automatically generates 'sensor_config.json'.
Zero manual file editing required.
"""

import os
import sys
import json
import ssl
import socket
import argparse
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, Tuple

DEFAULT_BACKEND_URL = "https://threattrack-kxqt.onrender.com"
DEFAULT_CONFIG_FILENAME = "sensor_config.json"


def mask_key(key: Optional[str]) -> str:
    """Mask sensitive keys for safe terminal printing."""
    if not key:
        return "(none)"
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"


def validate_backend_url(url: str) -> str:
    """Enforce valid HTTPS URL for cloud telemetry transmission."""
    url = url.strip().rstrip("/")
    parsed = urllib.parse.urlparse(url)
    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    if scheme not in ("http", "https"):
        raise ValueError(f"Invalid URL scheme '{scheme}'. Must be https:// or http:// (loopback).")

    is_loopback = host in ("127.0.0.1", "localhost", "::1", "testserver")
    if not is_loopback and scheme != "https":
        raise ValueError(f"Insecure backend URL rejected: '{url}'. Remote communication requires HTTPS.")

    return url


def check_existing_config(config_path: Path, force: bool = False) -> Tuple[bool, Optional[str]]:
    """
    Check if a valid sensor configuration already exists.
    Returns (can_proceed, sensor_id_if_exists).
    Prevents accidental overwriting of active sensors (e.g. sensor5).
    """
    if not config_path.exists():
        return True, None

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            sensor_id = data.get("sensor_id")
            has_key = bool(data.get("api_key"))

            if sensor_id and has_key:
                if not force:
                    return False, sensor_id
    except Exception:
        # If existing file is corrupted or empty, allow writing
        return True, None

    return True, None


def redeem_token(backend_url: str, token: str, timeout: float = 15.0) -> Dict[str, Any]:
    """
    Contact ThreatTrack backend over HTTPS to redeem one-time enrollment token.
    Tries primary endpoint /api/sensor/redeem-token and fallback /api/sensors/enroll.
    """
    payload = {
        "token": token.strip(),
        "hostname": socket.gethostname() or "windows-sensor",
        "sensor_version": "1.0.0-win"
    }
    json_bytes = json.dumps(payload).encode("utf-8")

    endpoints = [
        f"{backend_url}/api/sensor/redeem-token",
        f"{backend_url}/api/sensors/enroll",
        f"{backend_url}/api/sensor/enroll/redeem",
    ]

    last_error = None
    for url in endpoints:
        req = urllib.request.Request(
            url=url,
            data=json_bytes,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "ThreatTrack-Sensor-AutoEnroll/1.0"
            },
            method="POST"
        )

        ssl_ctx = ssl.create_default_context()
        # For local test loopback, allow relaxed SSL if self-signed
        if "127.0.0.1" in backend_url or "localhost" in backend_url:
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
                resp_data = resp.read().decode("utf-8")
                return json.loads(resp_data)
        except urllib.error.HTTPError as http_err:
            try:
                err_body = json.loads(http_err.read().decode("utf-8"))
                detail = err_body.get("detail", str(http_err))
            except Exception:
                detail = str(http_err)

            # If endpoint not found on this path, try next fallback
            if http_err.code == 404 and url != endpoints[-1]:
                last_error = f"HTTP 404: {detail}"
                continue

            if http_err.code == 410:
                raise RuntimeError(
                    f"Enrollment token rejected (HTTP 410): {detail}\n"
                    "This token has already been redeemed or has expired. Please generate a new token on the dashboard."
                ) from http_err
            elif http_err.code == 409:
                raise RuntimeError(
                    f"Enrollment token conflict (HTTP 409): {detail}\n"
                    "Token was redeemed concurrently. Please generate a new token on the dashboard."
                ) from http_err
            elif http_err.code == 404:
                raise RuntimeError(
                    f"Invalid token (HTTP 404): {detail}\n"
                    "Token not recognized. Please check the token copied from the dashboard."
                ) from http_err
            else:
                raise RuntimeError(f"Enrollment failed (HTTP {http_err.code}): {detail}") from http_err

        except urllib.error.URLError as url_err:
            last_error = f"Network connection failed: {url_err.reason}"
            continue
        except Exception as gen_err:
            last_error = str(gen_err)
            continue

    raise RuntimeError(f"Unable to reach enrollment API at {backend_url}. Error: {last_error}")


def save_and_validate_config(
    config_path: Path,
    sensor_id: str,
    api_key: str,
    backend_url: str,
    interface: Optional[str] = None
) -> Dict[str, Any]:
    """
    Atomically writes sensor_config.json and verifies file integrity.
    Never exposes raw API keys in exceptions or logs.
    """
    config_dict = {
        "sensor_id": sensor_id,
        "api_key": api_key,
        "backend_url": backend_url,
        "interface": interface or "Wi-Fi 3",
        "enrolled_at": datetime.now(timezone.utc).isoformat()
    }

    config_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = config_path.with_suffix(".tmp")

    try:
        with open(temp_path, "w", encoding="utf-8") as f:
            json.dump(config_dict, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        # Atomic replace
        temp_path.replace(config_path)

        # Validate by reading back
        with open(config_path, "r", encoding="utf-8") as f:
            verified = json.load(f)
            if verified.get("sensor_id") != sensor_id or not verified.get("api_key"):
                raise ValueError("Verification failed: written configuration file is incomplete.")

        return config_dict
    finally:
        if temp_path.exists():
            try:
                temp_path.unlink()
            except Exception:
                pass


def main():
    parser = argparse.ArgumentParser(
        description="ThreatTrack Automatic Sensor Enrollment Utility (PS 26145)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python enroll_sensor.py --token tt_enroll_xxxxxxxxxxxx
  python enroll_sensor.py
  python enroll_sensor.py --token tt_enroll_xxxxxxxxxxxx --backend-url https://threattrack-kxqt.onrender.com
        """
    )
    parser.add_argument(
        "--token", "-t",
        type=str,
        default=os.getenv("THREATTRACK_ENROLLMENT_TOKEN", None),
        help="One-time enrollment token issued by ThreatTrack dashboard"
    )
    parser.add_argument(
        "--backend-url", "-u",
        type=str,
        default=None,
        help=f"ThreatTrack HTTPS backend URL (default: {DEFAULT_BACKEND_URL})"
    )
    parser.add_argument(
        "--config-path", "-c",
        type=str,
        default=None,
        help="Target path for sensor_config.json (default: ./sensor_config.json)"
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default="Wi-Fi 3",
        help="Network interface to configure (default: 'Wi-Fi 3')"
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force overwrite of existing sensor_config.json"
    )

    args = parser.parse_args()

    # Determine configuration file path
    if args.config_path:
        config_path = Path(args.config_path).resolve()
    else:
        # Default to script directory or current working directory
        cwd_conf = Path("sensor_config.json").resolve()
        script_dir_conf = (Path(__file__).resolve().parent / "sensor_config.json").resolve()
        config_path = cwd_conf if cwd_conf.parent.exists() else script_dir_conf

    # Safety Guard: Check if existing valid sensor configuration exists (preserves sensor5)
    can_proceed, existing_sensor_id = check_existing_config(config_path, force=args.force)
    if not can_proceed:
        print("\n========================================================================")
        print(" [!] NOTICE: SENSOR CONFIGURATION ALREADY EXISTS")
        print("========================================================================")
        print(f" [*] Config File : {config_path}")
        print(f" [*] Enrolled ID : {existing_sensor_id}")
        print("\n [*] This device is already enrolled and ready to run.")
        print(" [*] To start the sensor, run:")
        print("     Start_ThreatTrack.bat")
        print("     or")
        print("     python backend\\scripts\\run_sensor.py")
        print("\n [!] If you intended to re-enroll this device with a new token, run:")
        print("     python enroll_sensor.py --force")
        print("========================================================================\n")
        sys.exit(0)

    # Resolve Backend URL
    backend_url = args.backend_url
    if not backend_url:
        backend_url = os.getenv("THREATTRACK_BACKEND_URL", os.getenv("NETRA_BACKEND_URL"))
    if not backend_url:
        # Check if existing config had a backend URL
        if config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    backend_url = json.load(f).get("backend_url")
            except Exception:
                pass
    if not backend_url:
        backend_url = DEFAULT_BACKEND_URL

    try:
        backend_url = validate_backend_url(backend_url)
    except ValueError as val_err:
        print(f"\n[X] Invalid Backend URL: {val_err}")
        sys.exit(1)

    # Prompt for enrollment token if not supplied via arguments or environment
    token = args.token
    if not token:
        print("\n========================================================================")
        print("    ThreatTrack - Automatic Sensor Enrollment Setup")
        print("========================================================================")
        print(f" [*] Backend URL : {backend_url}")
        print(" [*] Please copy your one-time enrollment token from the ThreatTrack dashboard.")
        print("     (Dashboard -> Live Monitor -> Add New Sensor)")
        print("------------------------------------------------------------------------")
        try:
            token = input("Enter Enrollment Token: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n[!] Setup cancelled by user.")
            sys.exit(1)

    if not token or len(token) < 8:
        print("\n[X] Error: A valid enrollment token is required.")
        sys.exit(1)

    print("\n[*] Contacting ThreatTrack cloud service over HTTPS...")
    print(f"[*] Endpoint   : {backend_url}")
    print(f"[*] Token Hash : {mask_key(token)}")

    try:
        result = redeem_token(backend_url=backend_url, token=token)
    except Exception as e:
        print(f"\n[X] ENROLLMENT FAILED: {e}\n")
        sys.exit(1)

    sensor_id = result.get("sensor_id")
    api_key = result.get("api_key")
    assigned_backend = result.get("backend_url") or backend_url

    if not sensor_id or not api_key:
        print("\n[X] Invalid response from backend: Missing sensor credentials.")
        sys.exit(1)

    print("[*] One-time token verified successfully!")
    print(f"[*] Issued Sensor ID: {sensor_id}")
    print(f"[*] Generating configuration at '{config_path}'...")

    try:
        save_and_validate_config(
            config_path=config_path,
            sensor_id=sensor_id,
            api_key=api_key,
            backend_url=assigned_backend,
            interface=args.interface
        )
    except Exception as save_err:
        print(f"\n[X] Failed to save configuration: {save_err}\n")
        sys.exit(1)

    print("\n========================================================================")
    print(" [✓] THREATTRACK SENSOR AUTOMATIC ENROLLMENT SUCCESSFUL!")
    print("========================================================================")
    print(f" [*] Enrolled Sensor ID : {sensor_id}")
    print(f" [*] Config File Created: {config_path}")
    print(f" [*] Cloud Backend URL  : {assigned_backend}")
    print(f" [*] Default Interface  : {args.interface or 'Wi-Fi 3'}")
    print(" [*] Authentication     : Permanent API key installed securely.")
    print("========================================================================")
    print("\n[NEXT STEPS]")
    print(" You can now start live monitoring on this machine:")
    print("   1. Run 'Start_ThreatTrack.bat' (Recommended - handles Administrator UAC)")
    print("   2. Or run: python backend\\scripts\\run_sensor.py")
    print("\n Your sensor will immediately appear as 'Online' on the ThreatTrack Live Monitor dashboard.\n")


if __name__ == "__main__":
    main()

