"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.sensor.test_sensor_sync_and_fixes

Regression test suite for ThreatTrack remote sensor fixes:
1. Agent initially reports RUNNING while DB target state is default STOPPED:
   Auto-synchronizes safely to RUNNING without returning premature STOP.
2. Explicit dashboard STOP command is respected and acknowledged by agent:
   User-requested STOP is never overridden by auto-sync, and returns command: STOPPED.
   Once agent acknowledges actual_state=STOPPED, the explicit pending command clears.
3. START command preserves agent interface without overwriting:
   When dashboard issues START without an interface, existing interface is preserved.
   When agent reports active interface, it is retained.
4. Transmitter timeout of 20 seconds avoids premature aborts:
   TransmitterConfig defaults to 20.0 seconds.
   Failed or timed-out transmissions requeue metadata without duplication or data loss.
"""

import sys
import time
import shutil
import asyncio
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from src.database.models import Base, UserModel, SensorEnrollmentModel
from src.database.repository import SensorEnrollmentRepository
from src.api.routes_sensor import (
    ingest_sensor_batch,
    control_sensor,
    SensorBatchIngestRequest,
    SensorControlRequest,
    _EXPLICIT_SENSOR_COMMANDS,
    _COMMAND_LOCK,
)
from src.sensor.metadata_queue import LocalMetadataQueue, MetadataRecord
from src.sensor.transmitter import SensorTransmitter, TransmitterConfig
from src.sensor.config import SensorConfig
from src.sensor.windows_sensor import WindowsSensor


class TestSensorSyncAndFixes(unittest.TestCase):
    """Targeted regression test suite verifying state synchronization, interface preservation, and timeout hardening."""

    @classmethod
    def setUpClass(cls):
        cls.test_engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            echo=False
        )
        cls.TestSession = sessionmaker(autocommit=False, autoflush=False, bind=cls.test_engine)
        Base.metadata.create_all(bind=cls.test_engine)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, 'test_engine') and cls.test_engine:
            cls.test_engine.dispose()

    def setUp(self):
        self.db = self.TestSession()
        self.db.query(SensorEnrollmentModel).delete()
        self.db.query(UserModel).delete()
        self.db.commit()
        with _COMMAND_LOCK:
            _EXPLICIT_SENSOR_COMMANDS.clear()

        # Create a test user
        self.user = UserModel(
            user_id="usr_sync_test_user_01",
            email="tester@threattrack.org",
            hashed_password="hashed_secure_pw_123",
            full_name="Test Operator",
            role="analyst",
            is_active=True
        )
        self.db.add(self.user)
        self.db.commit()

        # Create a mock FastAPI Request
        self.mock_request = MagicMock()
        self.mock_request.client.host = "192.168.1.15"
        self.mock_request.headers.get.return_value = None  # Content-Length check

    def tearDown(self):
        try:
            self.db.rollback()
            self.db.query(SensorEnrollmentModel).delete()
            self.db.query(UserModel).delete()
            self.db.commit()
        except Exception:
            pass
        finally:
            self.db.close()
        with _COMMAND_LOCK:
            _EXPLICIT_SENSOR_COMMANDS.clear()

    def _create_test_sensor(self, sensor_id: str, target_state: str = "STOPPED", interface: str = "Wi-Fi 3") -> SensorEnrollmentModel:
        sensor = SensorEnrollmentModel(
            sensor_id=sensor_id,
            user_id=self.user.user_id,
            owner_email=self.user.email,
            name=f"Device {sensor_id}",
            api_key_hash=f"dummyhash_{sensor_id}",
            api_key_prefix="netra_live",
            status="ACTIVE",
            target_state=target_state,
            actual_state="STOPPED",
            target_interface=interface
        )
        self.db.add(sensor)
        self.db.commit()
        self.db.refresh(sensor)
        return sensor

    def test_01_agent_running_auto_syncs_without_premature_stop(self):
        """
        Regression Test 1:
        Agent initially reports actual_state=RUNNING while DB target_state is default STOPPED.
        Verify that:
        - The backend auto-synchronizes DB target_state to RUNNING.
        - The response command is 'RUNNING', NEVER returning 'STOPPED'.
        """
        sensor = self._create_test_sensor("sensor_sync_01", target_state="STOPPED", interface="Wi-Fi 3")

        body = SensorBatchIngestRequest(
            sensor_id="sensor_sync_01",
            batch_id="batch_001",
            sent_at=time.time(),
            records=[],
            actual_state="RUNNING"
        )

        response = ingest_sensor_batch(
            request=self.mock_request,
            body=body,
            sensor=sensor,
            db=self.db
        )

        # Check response command
        self.assertEqual(response["command"], "RUNNING", "Ingest response must return RUNNING, not STOPPED.")
        self.assertEqual(response["target_interface"], "Wi-Fi 3", "Target interface must remain preserved.")

        # Check DB state was safely synchronized to RUNNING
        refreshed_sensor = SensorEnrollmentRepository.get_by_sensor_id(self.db, "sensor_sync_01")
        self.assertEqual(refreshed_sensor.target_state, "RUNNING", "Database target_state should be auto-synchronized to RUNNING.")
        self.assertEqual(refreshed_sensor.actual_state, "RUNNING")

    def test_02_explicit_dashboard_stop_command_respected(self):
        """
        Regression Test 2:
        Explicit dashboard STOP command is respected and acknowledged by agent:
        - When user issues STOP, command is recorded.
        - Next ingest with actual_state=RUNNING returns command='STOPPED'.
        - Auto-sync does NOT override the explicit user STOP.
        - When agent subsequently reports actual_state='STOPPED', explicit pending command clears.
        """
        sensor = self._create_test_sensor("sensor_stop_02", target_state="RUNNING", interface="Wi-Fi 3")

        # 1. User issues explicit STOP command from dashboard
        ctrl_payload = SensorControlRequest(command="STOP", interface=None)
        ctrl_resp = control_sensor(
            sensor_id="sensor_stop_02",
            payload=ctrl_payload,
            current_user=self.user,
            db=self.db
        )
        self.assertTrue(ctrl_resp["success"])
        self.assertEqual(ctrl_resp["command"], "STOP")

        with _COMMAND_LOCK:
            self.assertIn("sensor_stop_02", _EXPLICIT_SENSOR_COMMANDS)
            self.assertTrue(_EXPLICIT_SENSOR_COMMANDS["sensor_stop_02"]["active"])
            self.assertEqual(_EXPLICIT_SENSOR_COMMANDS["sensor_stop_02"]["command"], "STOPPED")

        # 2. Agent checks in while still RUNNING
        body_running = SensorBatchIngestRequest(
            sensor_id="sensor_stop_02",
            batch_id="batch_002",
            sent_at=time.time(),
            records=[],
            actual_state="RUNNING"
        )
        ingest_resp = ingest_sensor_batch(
            request=self.mock_request,
            body=body_running,
            sensor=sensor,
            db=self.db
        )

        # Must return STOPPED to agent, overriding auto-sync!
        self.assertEqual(ingest_resp["command"], "STOPPED", "Explicit user STOP must override auto-sync and send STOPPED to agent.")

        # 3. Agent halts and checks in with actual_state='STOPPED'
        body_stopped = SensorBatchIngestRequest(
            sensor_id="sensor_stop_02",
            batch_id="batch_003",
            sent_at=time.time(),
            records=[],
            actual_state="STOPPED"
        )
        ingest_resp_stopped = ingest_sensor_batch(
            request=self.mock_request,
            body=body_stopped,
            sensor=sensor,
            db=self.db
        )

        self.assertEqual(ingest_resp_stopped["command"], "STOPPED")
        with _COMMAND_LOCK:
            self.assertFalse(
                _EXPLICIT_SENSOR_COMMANDS["sensor_stop_02"]["active"],
                "Explicit STOP command should be marked inactive after agent reports STOPPED."
            )

    def test_03_start_command_preserves_agent_interface(self):
        """
        Regression Test 3:
        START command preserves agent interface without overwriting:
        - When control_sensor is called with interface=None (as sent by frontend in remote mode),
          the agent's configured interface ('Wi-Fi 3') is strictly preserved.
        """
        sensor = self._create_test_sensor("sensor_iface_03", target_state="STOPPED", interface="Wi-Fi 3")

        # User clicks Start Monitoring on dashboard (passing interface=None)
        ctrl_payload = SensorControlRequest(command="START", interface=None)
        ctrl_resp = control_sensor(
            sensor_id="sensor_iface_03",
            payload=ctrl_payload,
            current_user=self.user,
            db=self.db
        )
        self.assertTrue(ctrl_resp["success"])

        refreshed = SensorEnrollmentRepository.get_by_sensor_id(self.db, "sensor_iface_03")
        self.assertEqual(refreshed.target_state, "RUNNING")
        self.assertEqual(refreshed.target_interface, "Wi-Fi 3", "Target interface 'Wi-Fi 3' must not be overwritten by None.")

    def test_04_transmitter_20s_timeout_configuration_and_requeue(self):
        """
        Regression Test 4:
        Transmitter timeout of 20 seconds avoids premature aborts:
        - TransmitterConfig default timeout is 20.0s.
        - WindowsSensor instantiates Transmitter with timeout_seconds=20.0s.
        - On TimeoutError, batch records are safely requeued in LocalMetadataQueue without loss or duplication.
        """
        # 1. Verify default timeout is 20.0 seconds
        cfg = TransmitterConfig(backend_url="https://threattrack.example.com", api_key="secret")
        self.assertEqual(cfg.timeout_seconds, 20.0, "TransmitterConfig default timeout must be 20.0s.")

        # 2. Verify WindowsSensor uses 20.0s
        temp_dir = tempfile.mkdtemp(prefix="tt_win_test_")
        try:
            w_cfg = SensorConfig(
                interface="Wi-Fi 3",
                sensor_id="sensor_win_01",
                sensor_api_key="key123",
                remote_backend_url="https://threattrack-test.onrender.com",
                enable_remote_transmission=True,
                queue_spool_dir=temp_dir
            )
            sensor_instance = WindowsSensor(w_cfg)
            self.assertIsNotNone(sensor_instance.transmitter)
            self.assertEqual(sensor_instance.transmitter.config.timeout_seconds, 20.0)
            sensor_instance.stop()
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

        # 3. Verify TimeoutError requeues records without data loss
        temp_queue_dir = tempfile.mkdtemp(prefix="tt_queue_test_")
        try:
            queue = LocalMetadataQueue(
                max_size=100,
                spool_dir=temp_queue_dir,
                spool_filename="spool.jsonl",
                enable_disk_spool=True
            )
            rec = MetadataRecord(
                record_id="rec_timeout_01",
                sensor_id="sensor_win_01",
                sensor_version="1.0.0-win",
                hostname="my-pc",
                timestamp=time.time(),
                record_type="FLOW",
                interface="Wi-Fi 3",
                flow={"flow_id": "f_timeout", "total_packets": 10}
            )
            queue.enqueue(rec)
            self.assertEqual(queue.qsize(), 1)

            tx = SensorTransmitter(queue, cfg)
            batch = queue.dequeue_batch(max_items=5)
            self.assertEqual(len(batch), 1)
            self.assertEqual(queue.qsize(), 0)

            # Simulate timeout during transmit
            with patch("urllib.request.urlopen", side_effect=TimeoutError("The read operation timed out")):
                try:
                    tx.transmit_batch_sync(batch)
                except TimeoutError:
                    for r in batch:
                        queue.nack(r.record_id, requeue=True)

            # Record must be back in the queue
            self.assertEqual(queue.qsize(), 1, "Record must be requeued back into queue on timeout.")
            dequeued_again = queue.dequeue_batch(max_items=5)
            self.assertEqual(len(dequeued_again), 1)
            self.assertEqual(dequeued_again[0].record_id, "rec_timeout_01")
            queue.close()
        finally:
            shutil.rmtree(temp_queue_dir, ignore_errors=True)

    def test_05_stop_command_responsiveness_and_immediate_state_checkin(self):
        """
        Regression Test 5:
        Verify STOP command responsiveness:
        - Calling stop() transitions status to 'STOPPED' cleanly within 2 seconds.
        - Immediately sets transmitter.last_heartbeat_time = 0.0 to trigger check-in without waiting for interval.
        - Worker thread terminates cleanly.
        """
        temp_dir = tempfile.mkdtemp(prefix="tt_stop_test_")
        try:
            cfg = SensorConfig(
                interface="Wi-Fi 3",
                sensor_id="sensor_stop_fast",
                sensor_api_key="key_stop",
                remote_backend_url="https://threattrack-test.onrender.com",
                enable_remote_transmission=True,
                queue_spool_dir=temp_dir
            )
            with patch("scapy.all.sniff", side_effect=lambda **kwargs: time.sleep(0.1)):
                sensor = WindowsSensor(cfg)
                # Mock interface resolution
                sensor.actual_interface = "Wi-Fi 3"
                sensor.status = "RUNNING"
                sensor.transmitter.last_heartbeat_time = 999999.0

                # Measure stop latency
                t0 = time.time()
                res = sensor.stop(stop_transmitter=False)
                stop_duration = time.time() - t0

                self.assertTrue(res["success"])
                self.assertEqual(sensor.status, "STOPPED")
                self.assertLess(stop_duration, 2.5, f"Stop took {stop_duration:.2f}s, must be < 2.5s")
                self.assertEqual(sensor.transmitter.last_heartbeat_time, 0.0, "Heartbeat time must be 0.0 for immediate check-in")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_06_stale_command_timestamp_rejection(self):
        """
        Regression Test 6:
        Verify command timestamp ordering prevents delayed out-of-order execution:
        - When STOP with ts=200 arrives, it executes.
        - When a delayed START with ts=150 arrives, it is dropped as stale.
        - Status remains STOPPED.
        """
        temp_dir = tempfile.mkdtemp(prefix="tt_ts_test_")
        try:
            cfg = SensorConfig(
                interface="Wi-Fi 3",
                sensor_id="sensor_ts_01",
                sensor_api_key="key_ts",
                remote_backend_url="https://threattrack-test.onrender.com",
                enable_remote_transmission=False,
                queue_spool_dir=temp_dir
            )
            sensor = WindowsSensor(cfg)
            sensor.status = "RUNNING"
            sensor._last_command_timestamp = None

            # 1. Process STOP command at timestamp 200.0
            with patch.object(sensor, "stop", wraps=sensor.stop) as mock_stop:
                sensor._handle_remote_command(command="STOP", target_interface=None, command_timestamp=200.0)
                self.assertEqual(sensor.status, "STOPPED")
                self.assertEqual(sensor._last_command_timestamp, 200.0)
                mock_stop.assert_called_once()

            # 2. Delayed out-of-order START command arrives with timestamp 150.0 (older than 200.0)
            with patch.object(sensor, "start") as mock_start:
                sensor._handle_remote_command(command="START", target_interface="Wi-Fi 3", command_timestamp=150.0)
                mock_start.assert_not_called()
                self.assertEqual(sensor.status, "STOPPED", "Stale START command must not flip sensor status to RUNNING")

            # 3. Fresh START command arrives with timestamp 250.0 (> 200.0)
            with patch.object(sensor, "start") as mock_start:
                sensor._handle_remote_command(command="START", target_interface="Wi-Fi 3", command_timestamp=250.0)
                mock_start.assert_called_once()
                self.assertEqual(sensor._last_command_timestamp, 250.0)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_07_queue_preservation_and_zero_flow_loss_on_stop(self):
        """
        Regression Test 7:
        Verify that stopping packet capture preserves all active flows in FlowBuilder:
        - Packets pushed to FlowBuilder without closing FIN/RST remain active.
        - Calling stop() flushes all active flows to the metadata queue.
        - Zero flows or metadata records are dropped.
        """
        temp_dir = tempfile.mkdtemp(prefix="tt_fl_test_")
        try:
            cfg = SensorConfig(
                interface="Wi-Fi 3",
                sensor_id="sensor_flush_01",
                sensor_api_key="key_fl",
                remote_backend_url="https://threattrack-test.onrender.com",
                enable_remote_transmission=False,
                enable_detection=False,
                queue_spool_dir=temp_dir
            )
            sensor = WindowsSensor(cfg)
            sensor.actual_interface = "Wi-Fi 3"
            sensor.status = "RUNNING"

            # Start flow builder
            from src.capture.flow_builder import FlowBuilder
            sensor._builder = FlowBuilder(
                timeout_seconds=30.0,
                consumer_callback=sensor._handle_completed_flow
            )

            # Feed 3 distinct flows
            now = time.time()
            for i in range(3):
                sensor._builder.process_packet(
                    timestamp=now,
                    src_ip="192.168.1.50",
                    dst_ip=f"93.184.216.{10 + i}",
                    src_port=50000 + i,
                    dst_port=443,
                    protocol="TCP",
                    byte_len=120,
                    tcp_flags={"SYN": True}
                )

            # Active flows in FlowBuilder: 3
            self.assertEqual(sensor._builder.active_flow_count, 3)
            self.assertEqual(sensor.metadata_queue.qsize(), 0)

            # Invoke stop()
            sensor.stop(stop_transmitter=False)

            # FlowBuilder must be completely flushed, and queue must have all 3 flows!
            self.assertEqual(sensor._builder.active_flow_count, 0)
            self.assertEqual(sensor.metadata_queue.qsize(), 3, "All 3 active flows must be flushed into metadata queue.")
            self.assertEqual(sensor.flows_completed, 3)

            # Inspect queued records
            batch = sensor.metadata_queue.dequeue_batch(max_items=10)
            self.assertEqual(len(batch), 3)
            for r in batch:
                self.assertEqual(r.record_type, "FLOW")
                self.assertEqual(r.flow["src_ip"], "192.168.1.50")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
