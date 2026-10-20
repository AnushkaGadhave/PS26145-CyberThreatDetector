"""
Convenience entry script to launch NETRA Local Windows Sensor.
Example usage:
  python scripts/run_sensor.py --list-interfaces
  python scripts/run_sensor.py --interface "Wi-Fi 2" --duration 10
  python scripts/run_sensor.py --inspect-queue
"""

import sys
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from src.sensor.cli import main

if __name__ == "__main__":
    main()
