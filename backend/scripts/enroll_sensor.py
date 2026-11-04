#!/usr/bin/env python3
"""
Convenience wrapper to run enroll_sensor from backend/scripts/
"""
import sys
from pathlib import Path

# Add project root to sys.path
root_dir = Path(__file__).resolve().parent.parent.parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from enroll_sensor import main

if __name__ == "__main__":
    main()

