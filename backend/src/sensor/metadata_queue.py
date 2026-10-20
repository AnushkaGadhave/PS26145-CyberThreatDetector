"""
NETRA Local Windows Sensor - Metadata Queue Module
Provides a thread-safe, bounded, locally-spooled metadata queue interface
for buffering flow telemetry and threat events for future cloud transmission.
Zero cloud transmission occurs in this phase; records are staged locally.
"""

import os
import json
import time
import socket
import hashlib
import logging
import threading
from pathlib import Path
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Any, Optional, Union

logger = logging.getLogger(__name__)


@dataclass
class MetadataRecord:
    """
    Structured metadata payload queued for cloud ingest.
    Adheres strictly to metadata-only collection (zero packet payloads).
    """
    record_id: str
    sensor_id: str
    sensor_version: str
    hostname: str
    timestamp: float
    record_type: str  # 'FLOW', 'THREAT_ALERT', 'HEARTBEAT', 'SENSOR_STATUS'
    interface: str
    flow: Optional[Dict[str, Any]] = None
    validation: Optional[Dict[str, Any]] = None
    detection: Optional[Dict[str, Any]] = None
    delivery_status: str = "PENDING_LOCAL"  # 'PENDING_LOCAL', 'IN_FLIGHT', 'ACKED'
    retry_count: int = 0
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert record to JSON-serializable dictionary."""
        return asdict(self)

    def to_json(self) -> str:
        """Convert record to single-line JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "MetadataRecord":
        """Reconstruct MetadataRecord from dictionary."""
        return cls(**data)


class LocalMetadataQueue:
    """
    Thread-safe, bounded, locally-persisted metadata buffer.
    Maintains an in-memory FIFO queue for high-throughput consumers, alongside
    an append-only JSON Lines local disk spool for auditability and recovery.
    """
    def __init__(
        self,
        max_size: int = 10000,
        spool_dir: Union[str, Path] = "data/sensor_queue",
        spool_filename: str = "metadata_spool.jsonl",
        enable_disk_spool: bool = True
    ):
        self.max_size = max_size
        self.spool_dir = Path(spool_dir)
        self.spool_filename = spool_filename
        self.spool_path = self.spool_dir / self.spool_filename
        self.enable_disk_spool = enable_disk_spool

        self._queue: deque[MetadataRecord] = deque()
        self._lock = threading.Lock()
        self._condition = threading.Condition(self._lock)

        # Volumetric counters
        self.enqueued_count = 0
        self.dequeued_count = 0
        self.dropped_count = 0
        self.acked_count = 0
        self.nacked_count = 0

        # Unacked tracking for reliable at-least-once delivery semantics
        self._in_flight: Dict[str, MetadataRecord] = {}

        if self.enable_disk_spool:
            try:
                self.spool_dir.mkdir(parents=True, exist_ok=True)
            except Exception as e:
                logger.error(f"Failed to create spool directory {self.spool_dir}: {e}")

    def enqueue(self, record: Union[MetadataRecord, Dict[str, Any]]) -> bool:
        """
        Pushes a metadata record into the queue.
        If the queue exceeds max_size, drops the oldest record (backpressure handling)
        and increments the drop counter.
        """
        if isinstance(record, dict):
            # Auto-assign ID if missing
            if "record_id" not in record:
                raw_id = f"{record.get('timestamp', time.time())}_{record.get('record_type', 'flow')}_{time.time_ns()}"
                record["record_id"] = f"meta_{hashlib.sha256(raw_id.encode('utf-8')).hexdigest()[:12]}"
            meta_record = MetadataRecord.from_dict(record)
        else:
            meta_record = record

        with self._condition:
            if len(self._queue) >= self.max_size:
                # Evict oldest record to prevent unbounded memory growth
                evicted = self._queue.popleft()
                self.dropped_count += 1
                logger.warning(
                    f"[QUEUE BACKPRESSURE] LocalMetadataQueue full ({self.max_size}). "
                    f"Dropped oldest record: {evicted.record_id}. Total drops: {self.dropped_count}"
                )

            self._queue.append(meta_record)
            self.enqueued_count += 1
            self._condition.notify()

        # Write to local disk spool
        if self.enable_disk_spool:
            self._spool_to_disk(meta_record)

        return True

    def _spool_to_disk(self, record: MetadataRecord):
        """Append record to persistent JSONL spool."""
        try:
            line = record.to_json() + "\n"
            with open(self.spool_path, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            logger.error(f"Failed to append record {record.record_id} to spool file {self.spool_path}: {e}")

    def dequeue(self, timeout: Optional[float] = None) -> Optional[MetadataRecord]:
        """
        Pulls a single record from the queue (blocking if timeout > 0).
        Marks the record as IN_FLIGHT until acked.
        """
        with self._condition:
            if not self._queue:
                if timeout is not None and timeout > 0:
                    self._condition.wait(timeout=timeout)
                if not self._queue:
                    return None

            record = self._queue.popleft()
            self.dequeued_count += 1
            record.delivery_status = "IN_FLIGHT"
            self._in_flight[record.record_id] = record
            return record

    def dequeue_batch(self, max_items: int = 50, timeout: Optional[float] = None) -> List[MetadataRecord]:
        """
        Pulls a batch of records up to max_items.
        Useful for future bulk transmission to the cloud backend.
        """
        batch: List[MetadataRecord] = []
        with self._condition:
            if not self._queue and timeout is not None and timeout > 0:
                self._condition.wait(timeout=timeout)

            while self._queue and len(batch) < max_items:
                record = self._queue.popleft()
                self.dequeued_count += 1
                record.delivery_status = "IN_FLIGHT"
                self._in_flight[record.record_id] = record
                batch.append(record)

        return batch

    def ack(self, record_id: str) -> bool:
        """Acknowledge successful processing or transmission of a queued record."""
        with self._lock:
            record = self._in_flight.pop(record_id, None)
            if record:
                self.acked_count += 1
                record.delivery_status = "ACKED"
                return True
            return False

    def ack_batch(self, record_ids: List[str]) -> int:
        """Acknowledge a batch of processed records."""
        count = 0
        with self._lock:
            for rid in record_ids:
                if rid in self._in_flight:
                    self._in_flight.pop(rid)
                    self.acked_count += 1
                    count += 1
        return count

    def nack(self, record_id: str, requeue: bool = True) -> bool:
        """
        Negative acknowledgement; returns unacknowledged record back to the front
        of the queue for retry.
        """
        with self._condition:
            record = self._in_flight.pop(record_id, None)
            if record:
                self.nacked_count += 1
                record.retry_count += 1
                record.delivery_status = "PENDING_LOCAL"
                if requeue and len(self._queue) < self.max_size:
                    self._queue.appendleft(record)
                    self._condition.notify()
                return True
            return False

    def peek(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Non-destructive inspection of pending items in queue."""
        with self._lock:
            sample = list(self._queue)[:limit]
            return [r.to_dict() for r in sample]

    def qsize(self) -> int:
        """Return the current number of pending items in the in-memory queue."""
        with self._lock:
            return len(self._queue)

    def is_empty(self) -> bool:
        """Check if queue is empty."""
        with self._lock:
            return len(self._queue) == 0

    def stats(self) -> Dict[str, Any]:
        """Return operational telemetry metrics for the local queue."""
        with self._lock:
            q_len = len(self._queue)
            in_flight_len = len(self._in_flight)
            spool_size = self.spool_path.stat().st_size if self.spool_path.exists() else 0

            return {
                "pending_queue_size": q_len,
                "in_flight_size": in_flight_len,
                "max_size": self.max_size,
                "enqueued_total": self.enqueued_count,
                "dequeued_total": self.dequeued_count,
                "dropped_total": self.dropped_count,
                "acked_total": self.acked_count,
                "nacked_total": self.nacked_count,
                "spool_file_path": str(self.spool_path) if self.enable_disk_spool else None,
                "spool_file_size_bytes": spool_size
            }

    def clear(self):
        """Clear in-memory queue and in-flight tracking (does not delete spool file)."""
        with self._lock:
            self._queue.clear()
            self._in_flight.clear()

    def close(self):
        """Flush and release resources."""
        with self._condition:
            self._condition.notify_all()
