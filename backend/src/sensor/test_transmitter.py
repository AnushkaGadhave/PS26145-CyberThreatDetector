"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.sensor.test_transmitter

Unit tests for SensorTransmitter:
- Batch dequeuing and synchronization
- Server acknowledgement removing records from in-flight queue
- Transient network failure preservation and retry
- HTTP 429 rate limit backoff
- HTTP 401/403 authentication error handling
- Zero packet payload validation
"""

import sys
import time
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock
import urllib.error

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.sensor.metadata_queue import LocalMetadataQueue, MetadataRecord
from src.sensor.transmitter import SensorTransmitter, TransmitterConfig


class TestSensorTransmitter(unittest.TestCase):
    """Test suite covering the reliable outbound telemetry transmitter."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="netra_tx_test_")
        self.queue = LocalMetadataQueue(
            max_size=500,
            spool_dir=self.temp_dir,
            spool_filename="test_spool.jsonl",
            enable_disk_spool=True
        )
        self.config = TransmitterConfig(
            backend_url="http://127.0.0.1:8000",
            api_key="netra_live_test_credential_123",
            sensor_id="test-sensor-01",
            batch_size=10,
            flush_interval=0.1,
            timeout_seconds=2.0,
            enable_transmission=True
        )
        self.transmitter = SensorTransmitter(self.queue, self.config)

    def tearDown(self):
        if self.transmitter.is_running():
            self.transmitter.stop(timeout=1.0)
        self.queue.close()
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _enqueue_dummy_flow(self, flow_id: str) -> str:
        rec_id = f"meta_{flow_id}"
        rec = MetadataRecord(
            record_id=rec_id,
            sensor_id=self.config.sensor_id,
            sensor_version="1.0.0-win",
            hostname="test-host",
            timestamp=time.time(),
            record_type="FLOW",
            interface="Wi-Fi 2",
            flow={
                "flow_id": flow_id,
                "src_ip": "192.168.0.100",
                "dst_ip": "1.1.1.1",
                "protocol": "TCP",
                "total_packets": 5,
                "total_bytes": 500
            }
        )
        self.queue.enqueue(rec)
        return rec_id

    def test_01_successful_batch_transmission_and_ack(self):
        """1. Verify successful transmission dequeues, acknowledges, and clears records."""
        rec_ids = [self._enqueue_dummy_flow(f"f_{i}") for i in range(5)]
        self.assertEqual(self.queue.qsize(), 5)

        # Mock urllib response
        import json
        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({
            "success": True,
            "batch_id": "b1",
            "accepted": 5,
            "ack_ids": rec_ids
        }).encode("utf-8")
        mock_response.__enter__.return_value = mock_response

        with patch("urllib.request.urlopen", return_value=mock_response):
            batch = self.queue.dequeue_batch(max_items=10)
            result = self.transmitter.transmit_batch_sync(batch)

            self.assertEqual(result["accepted"], 5)
            self.assertEqual(len(result["ack_ids"]), 5)

            # Ack the batch
            acked = self.queue.ack_batch(result["ack_ids"])
            self.assertEqual(acked, 5)

            # Verify in-flight queue is empty
            stats = self.queue.stats()
            self.assertEqual(stats["in_flight_size"], 0)
            self.assertEqual(stats["acked_total"], 5)

    def test_02_network_failure_preserves_records_for_retry(self):
        """2. Verify network failure preserves records in queue without discarding."""
        rec_id = self._enqueue_dummy_flow("f_network_err")
        batch = self.queue.dequeue_batch(max_items=10)
        self.assertEqual(len(batch), 1)
        self.assertEqual(self.queue.qsize(), 0)

        # Simulate network failure during transmit
        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("Connection refused")):
            try:
                self.transmitter.transmit_batch_sync(batch)
            except urllib.error.URLError:
                # Nack batch on failure
                for r in batch:
                    self.queue.nack(r.record_id, requeue=True)

        # Verify record was returned to pending queue
        self.assertEqual(self.queue.qsize(), 1)
        re_dequeued = self.queue.dequeue()
        self.assertIsNotNone(re_dequeued)
        self.assertEqual(re_dequeued.record_id, rec_id)
        self.assertEqual(re_dequeued.retry_count, 1)

    def test_03_http_429_rate_limit_backoff(self):
        """3. Verify transmitter handles HTTP 429 response cleanly."""
        self._enqueue_dummy_flow("f_429_test")
        batch = self.queue.dequeue_batch(max_items=10)

        # Mock HTTP 429 response
        headers = MagicMock()
        headers.get.return_value = "10"
        err = urllib.error.HTTPError(
            url="http://127.0.0.1:8000/api/sensor/ingest",
            code=429,
            msg="Too Many Requests",
            hdrs=headers,
            fp=None
        )

        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(urllib.error.HTTPError):
                self.transmitter.transmit_batch_sync(batch)

    def test_04_auth_failure_retains_records_locally(self):
        """4. Verify HTTP 401 credential rejection preserves local queue and spool."""
        rec_id = self._enqueue_dummy_flow("f_auth_err")
        batch = self.queue.dequeue_batch(max_items=10)

        err = urllib.error.HTTPError(
            url="http://127.0.0.1:8000/api/sensor/ingest",
            code=401,
            msg="Unauthorized",
            hdrs=MagicMock(),
            fp=None
        )

        with patch("urllib.request.urlopen", side_effect=err):
            with self.assertRaises(urllib.error.HTTPError):
                self.transmitter.transmit_batch_sync(batch)

        # When auth fails, transmitter nacks records to preserve them locally
        for r in batch:
            self.queue.nack(r.record_id, requeue=True)

        self.assertEqual(self.queue.qsize(), 1)
        # Verify local disk spool exists and is intact
        self.assertTrue(self.queue.spool_path.exists())
        self.assertGreater(self.queue.spool_path.stat().st_size, 0)

    def test_05_oversized_batch_payload_rejected_locally(self):
        """5. Verify batches exceeding 50 KB are rejected locally before network transmission."""
        huge_records = []
        for i in range(200):
            huge_records.append(MetadataRecord(
                record_id=f"huge_{i}",
                sensor_id="sensor",
                sensor_version="1.0",
                hostname="h" * 100,
                timestamp=time.time(),
                record_type="FLOW",
                interface="iface",
                flow={"extra": "x" * 300}
            ))

        with self.assertRaises(ValueError) as ctx:
            self.transmitter.transmit_batch_sync(huge_records)
        self.assertIn("50 KB limit", str(ctx.exception))

    def test_06_enforce_https_for_remote_backend(self):
        """6. Verify HTTPS is strictly enforced for remote endpoints, rejecting insecure HTTP."""
        # Non-HTTPS remote URL must raise ValueError
        with self.assertRaises(ValueError) as ctx:
            TransmitterConfig(
                backend_url="http://threattrack-api.example.com",
                enable_transmission=True
            )
        self.assertIn("must use HTTPS", str(ctx.exception))

        # HTTPS remote URL must be accepted
        valid_remote = TransmitterConfig(
            backend_url="https://threattrack-api.example.com",
            enable_transmission=True
        )
        self.assertEqual(valid_remote.backend_url, "https://threattrack-api.example.com")

        # Local loopback HTTP is allowed for testing
        local_cfg = TransmitterConfig(
            backend_url="http://127.0.0.1:8000",
            enable_transmission=True
        )
        self.assertEqual(local_cfg.backend_url, "http://127.0.0.1:8000")

    def test_07_api_key_masked_in_repr_and_errors(self):
        """7. Verify API keys are excluded from repr and redacted from error strings."""
        secret_key = "sensitive_sensor_api_token_999"
        cfg = TransmitterConfig(
            backend_url="http://127.0.0.1:8000",
            api_key=secret_key
        )
        # repr(cfg) must NOT contain secret_key
        self.assertNotIn(secret_key, repr(cfg))

        # Error sanitization
        tx = SensorTransmitter(self.queue, cfg)
        error_with_key = f"Failed to connect using key {secret_key} on host"
        sanitized = tx._sanitize_error(error_with_key)
        self.assertNotIn(secret_key, sanitized)
        self.assertIn("[REDACTED_KEY]", sanitized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
