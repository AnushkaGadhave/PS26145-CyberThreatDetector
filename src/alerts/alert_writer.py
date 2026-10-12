"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.alerts.alert_writer

Thread-safe streaming alert persistence to JSON Lines and CSV.
Incrementally appends records without full file rewrites.
"""

import json
import threading
import logging
from pathlib import Path
from typing import Optional, Dict, Any, List
import pandas as pd

from src.alerts.alert_schema import ThreatAlert

logger = logging.getLogger(__name__)


class AlertWriter:
    """
    Streaming alert writer for live threat notifications.
    """
    def __init__(
        self,
        jsonl_path: str = "data/processed/live/alerts/threat_alerts.jsonl",
        csv_path: Optional[str] = "data/processed/live/alerts/threat_alerts.csv"
    ):
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.csv_path = Path(csv_path) if csv_path else None
        self._lock = threading.Lock()

        if self.jsonl_path:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        if self.csv_path:
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)

        self._written_count = 0

    @property
    def written_count(self) -> int:
        return self._written_count

    def write_alert(self, alert: ThreatAlert):
        """Write a single ThreatAlert incrementally to JSONL and CSV."""
        if alert is None:
            return

        with self._lock:
            # 1. Write to JSON Lines
            if self.jsonl_path:
                try:
                    with open(self.jsonl_path, 'a', encoding='utf-8') as f:
                        f.write(alert.to_json() + '\n')
                except Exception as e:
                    logger.error(f"Error writing alert to JSONL {self.jsonl_path}: {e}")

            # 2. Write to CSV
            if self.csv_path:
                try:
                    write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
                    alert_dict = alert.to_dict()
                    # Convert complex nested evidence list to JSON string for CSV compatibility
                    alert_dict['evidence'] = json.dumps(alert_dict.get('evidence', []))
                    df = pd.DataFrame([alert_dict])
                    df.to_csv(self.csv_path, mode='a', header=write_header, index=False)
                except Exception as e:
                    logger.error(f"Error writing alert to CSV {self.csv_path}: {e}")

            self._written_count += 1
