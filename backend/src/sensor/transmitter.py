"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.sensor.transmitter

Reliable outbound HTTPS telemetry transmitter for the NETRA Windows Sensor.
Safely dequeues flow and threat metadata from LocalMetadataQueue and transmits
bounded batches to the configured cloud backend over authenticated HTTPS.

Operational Guarantees:
- Strictly outbound-only: Never requires opening listening inbound ports on the sensor host.
- Zero packet payloads: Exclusively transmits MetadataRecord flow statistics and explainable threat alerts.
- Bounded batches: Enforces maximum batch limits (<= 50 records) and request payload limits (< 50 KB).
- Safe retry with exponential backoff: Preserves records in memory and persistent disk spool during network outages.
- Exact acknowledgement: Records are only cleared from the queue when positively acknowledged by the backend.
- Rate-limit aware: Automatically honors HTTP 429 Retry-After intervals.
"""

import time
import uuid
import json
import random
import logging
import threading
import urllib.request
import urllib.error
import socket
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass

from src.sensor.metadata_queue import LocalMetadataQueue, MetadataRecord

logger = logging.getLogger(__name__)


@dataclass
class TransmitterConfig:
    """Configuration options for the outbound telemetry transmitter."""
    backend_url: str = "http://127.0.0.1:8000"
    api_key: str = ""
    sensor_id: str = "netra-sensor-win"
    sensor_version: str = "1.0.0-win"
    batch_size: int = 25
    flush_interval: float = 2.0
    timeout_seconds: float = 5.0
    max_retries: int = 5
    backoff_base: float = 1.0
    backoff_max: float = 30.0
    enable_transmission: bool = True


class SensorTransmitter:
    """
    Background worker thread that reliably drains records from LocalMetadataQueue
    and transmits them via HTTP/HTTPS POST to /api/sensor/ingest.
    """
    def __init__(
        self,
        queue: LocalMetadataQueue,
        config: Optional[TransmitterConfig] = None,
        status_provider: Optional[Callable[[], str]] = None,
        command_handler: Optional[Callable[[str, Optional[str]], None]] = None
    ):
        self.queue = queue
        self.config = config or TransmitterConfig()
        self.status_provider = status_provider
        self.command_handler = command_handler
        self.last_heartbeat_time: float = 0.0
        self.heartbeat_interval: float = 3.0

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Telemetry metrics
        self.batches_sent = 0
        self.records_sent = 0
        self.records_acked = 0
        self.last_upload_time: Optional[float] = None
        self.consecutive_errors = 0
        self.last_error: Optional[str] = None
        self.auth_failed = False

    def get_current_status(self) -> str:
        """Returns the actual operational status reported by the sensor engine."""
        if self.status_provider:
            try:
                return self.status_provider()
            except Exception:
                pass
        return "RUNNING"

    def start(self):
        """Start the background transmitter thread."""
        with self._lock:
            if self._running:
                return
            if not self.config.enable_transmission:
                logger.info("Outbound transmission is disabled in config.")
                return
            if not self.config.api_key:
                logger.warning("No sensor API key provided. Transmitter cannot authenticate; staying idle.")
                return

            self._running = True
            self.auth_failed = False
            self.consecutive_errors = 0
            self._thread = threading.Thread(
                target=self._worker_loop,
                name="NETRA-SensorTransmitter",
                daemon=True
            )
            self._thread.start()
            logger.info(
                f"ThreatTrack Sensor Transmitter started. Target: {self.config.backend_url}/api/sensor/ingest "
                f"(Sensor ID: {self.config.sensor_id})"
            )

    def stop(self, timeout: float = 5.0):
        """Gracefully stop the transmitter thread."""
        with self._lock:
            if not self._running:
                return
            self._running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
            logger.info("ThreatTrack Sensor Transmitter stopped cleanly.")

    def is_running(self) -> bool:
        """Check if transmitter thread is active."""
        with self._lock:
            return self._running and self._thread is not None and self._thread.is_alive()

    def transmit_batch_sync(self, batch: List[MetadataRecord]) -> Dict[str, Any]:
        """
        Synchronously transmits a single batch of records to the backend.
        Used by the worker loop and directly in test harnesses.
        Returns the parsed backend response dict.
        Raises urllib.error.HTTPError, urllib.error.URLError, or ValueError on failure.
        """
        if not batch:
            return {"accepted": 0, "ack_ids": []}

        endpoint = f"{self.config.backend_url.rstrip('/')}/api/sensor/ingest"
        batch_id = f"batch_{int(time.time() * 1000)}_{uuid.uuid4().hex[:8]}"

        payload = {
            "sensor_id": self.config.sensor_id,
            "batch_id": batch_id,
            "sent_at": time.time(),
            "actual_state": self.get_current_status(),
            "records": [r.to_dict() for r in batch]
        }

        body_bytes = json.dumps(payload).encode("utf-8")

        # Ensure bounded request size
        if len(body_bytes) > 51200:
            raise ValueError(f"Batch payload exceeds 50 KB limit ({len(body_bytes)} bytes)")

        req = urllib.request.Request(
            url=endpoint,
            data=body_bytes,
            headers={
                "Content-Type": "application/json",
                "X-Sensor-Key": self.config.api_key,
                "User-Agent": f"NETRA-Sensor/{self.config.sensor_version}"
            },
            method="POST"
        )

        with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
            resp_body = resp.read().decode("utf-8")
            result = json.loads(resp_body)

            # Process remote control command from backend if present
            backend_cmd = result.get("command")
            target_iface = result.get("target_interface")
            if backend_cmd and self.command_handler:
                try:
                    self.command_handler(backend_cmd, target_iface)
                except Exception as cmd_err:
                    logger.error(f"Error executing remote command '{backend_cmd}': {cmd_err}")

            return result

    def _worker_loop(self):
        """Core background loop that dequeues batches, transmits, and manages retries."""
        while self._running:
            # If authentication failed previously, pause transmission to prevent hammering server
            if self.auth_failed:
                time.sleep(5.0)
                continue

            try:
                # Dequeue batch of records up to configured batch size
                batch = self.queue.dequeue_batch(
                    max_items=self.config.batch_size,
                    timeout=self.config.flush_interval
                )

                if not batch:
                    # Queue is empty: send idle heartbeat to report health and poll commands
                    now = time.time()
                    if now - self.last_heartbeat_time >= self.heartbeat_interval:
                        hostname = "sensor-client"
                        try:
                            hostname = socket.gethostname()
                        except Exception:
                            pass
                        hb_rec = MetadataRecord(
                            record_id=f"hb_{int(now * 1000)}_{uuid.uuid4().hex[:6]}",
                            sensor_id=self.config.sensor_id,
                            sensor_version=self.config.sensor_version,
                            hostname=hostname,
                            timestamp=now,
                            record_type="HEARTBEAT",
                            interface="heartbeat"
                        )
                        try:
                            self.transmit_batch_sync([hb_rec])
                            self.last_heartbeat_time = now
                        except Exception as hb_err:
                            logger.debug(f"Idle heartbeat attempt failed: {hb_err}")
                    time.sleep(0.5)
                    continue

                # Transmit batch
                try:
                    result = self.transmit_batch_sync(batch)

                    # Successful transmission: process acknowledgements
                    ack_ids = result.get("ack_ids", [])
                    if ack_ids:
                        self.queue.ack_batch(ack_ids)
                        self.records_acked += len(ack_ids)

                    self.batches_sent += 1
                    self.records_sent += len(batch)
                    self.last_upload_time = time.time()
                    self.consecutive_errors = 0
                    self.last_error = None

                    logger.debug(
                        f"Transmitted batch {result.get('batch_id')}: "
                        f"{result.get('accepted', 0)} accepted, {result.get('duplicate', 0)} duplicate."
                    )

                except urllib.error.HTTPError as http_err:
                    status_code = http_err.code
                    self.last_error = f"HTTP {status_code}: {http_err.reason}"
                    self.consecutive_errors += 1

                    if status_code in (401, 403):
                        # Authentication or authorization failed
                        logger.error(
                            f"[TRANSMITTER AUTH ERROR] Backend rejected sensor credential: {self.last_error}. "
                            "Halting transmission. Queued records remain preserved locally."
                        )
                        self.auth_failed = True
                        # Requeue items so they remain in memory and on disk spool
                        for rec in batch:
                            self.queue.nack(rec.record_id, requeue=True)
                        time.sleep(5.0)

                    elif status_code == 429:
                        # Rate limit exceeded
                        retry_after = 15
                        try:
                            retry_header = http_err.headers.get("Retry-After")
                            if retry_header:
                                retry_after = max(1, int(retry_header))
                        except Exception:
                            pass

                        logger.warning(
                            f"[TRANSMITTER RATE LIMIT] HTTP 429 Too Many Requests. "
                            f"Backing off for {retry_after}s. Requeuing {len(batch)} records."
                        )
                        for rec in batch:
                            self.queue.nack(rec.record_id, requeue=True)
                        time.sleep(retry_after)

                    else:
                        # Server error (5xx) or client error (4xx)
                        logger.warning(
                            f"[TRANSMITTER HTTP ERROR] Transmission failed ({self.last_error}). "
                            f"Requeuing batch of {len(batch)} records."
                        )
                        for rec in batch:
                            self.queue.nack(rec.record_id, requeue=True)
                        self._apply_backoff()

                except (urllib.error.URLError, TimeoutError, OSError) as net_err:
                    # Transient network outage or backend unreachable
                    self.last_error = f"Network error: {net_err}"
                    self.consecutive_errors += 1
                    logger.warning(
                        f"[TRANSMITTER NETWORK OFFLINE] Could not reach backend ({net_err}). "
                        f"Requeuing {len(batch)} records. Local spool intact."
                    )
                    for rec in batch:
                        self.queue.nack(rec.record_id, requeue=True)
                    self._apply_backoff()

                except Exception as ex:
                    # General unexpected error
                    self.last_error = f"Unexpected error: {ex}"
                    self.consecutive_errors += 1
                    logger.error(f"[TRANSMITTER ERROR] {ex}", exc_info=True)
                    for rec in batch:
                        self.queue.nack(rec.record_id, requeue=True)
                    self._apply_backoff()

            except Exception as loop_ex:
                logger.error(f"[TRANSMITTER LOOP ERROR] {loop_ex}", exc_info=True)
                time.sleep(1.0)

    def _apply_backoff(self):
        """Compute and sleep for exponential backoff with random jitter."""
        factor = min(self.consecutive_errors, 6)
        base_delay = min(self.config.backoff_max, self.config.backoff_base * (2 ** factor))
        jitter = random.uniform(0.1, 0.5)
        delay = base_delay + jitter
        logger.debug(f"Applying transmitter backoff: {delay:.2f}s (consecutive errors: {self.consecutive_errors})")
        time.sleep(delay)

    def get_status(self) -> Dict[str, Any]:
        """Return operational telemetry for the outbound transmitter."""
        with self._lock:
            now = time.time()
            is_connected = (
                self._running
                and not self.auth_failed
                and self.consecutive_errors == 0
                and self.last_upload_time is not None
                and (now - self.last_upload_time) < 60.0
            )

            return {
                "is_running": self._running,
                "backend_url": self.config.backend_url,
                "sensor_id": self.config.sensor_id,
                "batches_sent": self.batches_sent,
                "records_sent": self.records_sent,
                "records_acked": self.records_acked,
                "last_upload_time": self.last_upload_time,
                "consecutive_errors": self.consecutive_errors,
                "last_error": self.last_error,
                "auth_failed": self.auth_failed,
                "is_connected": is_connected
            }
