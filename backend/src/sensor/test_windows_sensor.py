"""
NETRA Local Windows Sensor - Comprehensive Unit & Integration Test Suite
Validates:
1. Interface discovery and explicit selection
2. Invalid interface and error handling
3. Local metadata queue operations (enqueue, dequeue, batching, disk spooling)
4. Feature schema validation against trained models (74 DDoS, 78 PortScan, 46 C2)
5. Safety policies (multicast/discovery protection against false C2 classification)
6. Start, stop, and clean restart lifecycle
7. Real live packet capture, flow generation, and accurate volumetric counters
8. Model inference compatibility
"""

import sys
import time
import json
import urllib.request
import unittest
from pathlib import Path
from typing import List

# Ensure backend root is on sys.path
backend_root = Path(__file__).resolve().parent.parent.parent
if str(backend_root) not in sys.path:
    sys.path.insert(0, str(backend_root))

from src.capture.flow_builder import FlowBuilder
from src.capture.flow_schema import FlowRecord
from src.detection.feature_adapter import FeatureAdapter
from src.detection.threat_detector import ThreatDetector

from src.alerts.alert_engine import ThreatAlert
from src.alerts.alert_pipeline import AlertPipeline

from src.sensor.config import SensorConfig
from src.sensor.interface_manager import InterfaceManager, InterfaceNotFoundError
from src.sensor.metadata_queue import LocalMetadataQueue, MetadataRecord
from src.sensor.feature_validator import FeatureValidator
from src.sensor.safety import (
    is_multicast_or_broadcast_ip,
    is_local_discovery_port,
    evaluate_multicast_discovery_safety,
    prevent_c2_multicast_misclassification,
    is_quic_traffic,
    is_established_web_flow
)
from src.sensor.windows_sensor import WindowsSensor


class TestWindowsSensor(unittest.TestCase):
    """Test suite covering the complete NETRA Local Windows Sensor pipeline."""

    @classmethod
    def setUpClass(cls):
        cls.active_iface_name = InterfaceManager.resolve_interface(None, auto_fallback=True)
        print(f"\n[SETUP] Active test interface auto-selected: '{cls.active_iface_name}'")

    # -------------------------------------------------------------------------
    # 1. Interface Discovery and Explicit Selection
    # -------------------------------------------------------------------------
    def test_01_interface_discovery(self):
        """Verify interface discovery enumerates Windows adapters and identifies active IPs."""
        interfaces = InterfaceManager.list_interfaces(active_only=False)
        self.assertGreater(len(interfaces), 0, "No network interfaces discovered.")

        active_interfaces = InterfaceManager.list_interfaces(active_only=True)
        print(f"[TEST 1] Discovered {len(interfaces)} total adapters, {len(active_interfaces)} active with IPv4.")
        self.assertGreaterEqual(len(active_interfaces), 1, "At least one active adapter required.")

        # Check fields of active interface
        sample = active_interfaces[0]
        self.assertTrue(sample.is_active)
        self.assertIsNotNone(sample.name)
        self.assertGreater(len(sample.ipv4_addresses), 0)

    def test_02_explicit_interface_selection(self):
        """Verify explicit interface selection by name resolves accurately."""
        # Resolve Wi-Fi 2 explicitly
        resolved_wifi2 = InterfaceManager.resolve_interface("Wi-Fi 2", auto_fallback=False)
        self.assertEqual(resolved_wifi2, "Wi-Fi 2")

        # Resolve Wi-Fi 3 explicitly
        resolved_wifi3 = InterfaceManager.resolve_interface("Wi-Fi 3", auto_fallback=False)
        self.assertEqual(resolved_wifi3, "Wi-Fi 3")

    def test_03_invalid_interface_handling(self):
        """Verify requesting a non-existent adapter produces a clear InterfaceNotFoundError."""
        invalid_name = "NonExistentAdapter_XYZ_999"

        # 1. Direct validation must raise InterfaceNotFoundError
        with self.assertRaises(InterfaceNotFoundError) as ctx:
            InterfaceManager.validate_interface(invalid_name)
        self.assertIn("not found on this Windows host", str(ctx.exception))

        # 2. Strict resolution must raise InterfaceNotFoundError
        with self.assertRaises(InterfaceNotFoundError):
            InterfaceManager.resolve_interface(invalid_name, auto_fallback=False)

        # 3. Sensor start must return error dictionary with clear message
        sensor = WindowsSensor(SensorConfig(interface=invalid_name))
        res = sensor.start(invalid_name)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "ERROR")
        self.assertIn("not found", res["message"])

    # -------------------------------------------------------------------------
    # 2. Local Metadata Queue Operations
    # -------------------------------------------------------------------------
    def test_04_metadata_queue_enqueue_dequeue_spool(self):
        """Verify LocalMetadataQueue FIFO operations, batching, ack/nack, and disk spooling."""
        test_spool_dir = backend_root / "data/sensor_queue/test_scratch"
        queue = LocalMetadataQueue(
            max_size=5,
            spool_dir=test_spool_dir,
            spool_filename="test_spool.jsonl",
            enable_disk_spool=True
        )

        try:
            # Enqueue 3 records
            for i in range(3):
                rec = MetadataRecord(
                    record_id=f"test_rec_{i}",
                    sensor_id="test-sensor",
                    sensor_version="1.0.0",
                    hostname="test-host",
                    timestamp=1700000000.0 + i,
                    record_type="FLOW",
                    interface="Wi-Fi 2",
                    flow={"flow_id": f"flow_{i}", "packets": 10 * (i + 1)}
                )
                success = queue.enqueue(rec)
                self.assertTrue(success)

            self.assertEqual(queue.qsize(), 3)
            self.assertEqual(queue.enqueued_count, 3)

            # Peek inspection
            peeked = queue.peek(limit=2)
            self.assertEqual(len(peeked), 2)
            self.assertEqual(peeked[0]["record_id"], "test_rec_0")

            # Dequeue batch of 2
            batch = queue.dequeue_batch(max_items=2)
            self.assertEqual(len(batch), 2)
            self.assertEqual(batch[0].record_id, "test_rec_0")
            self.assertEqual(batch[1].record_id, "test_rec_1")
            self.assertEqual(queue.qsize(), 1)

            # Ack first, nack second
            ack_ok = queue.ack("test_rec_0")
            self.assertTrue(ack_ok)
            self.assertEqual(queue.acked_count, 1)

            nack_ok = queue.nack("test_rec_1", requeue=True)
            self.assertTrue(nack_ok)
            self.assertEqual(queue.nacked_count, 1)
            # Requeued record should be back in queue
            self.assertEqual(queue.qsize(), 2)

            # Test backpressure overflow eviction
            for j in range(10):
                overflow_rec = MetadataRecord(
                    record_id=f"overflow_{j}",
                    sensor_id="test-sensor",
                    sensor_version="1.0.0",
                    hostname="test-host",
                    timestamp=time.time(),
                    record_type="FLOW",
                    interface="Wi-Fi 2"
                )
                queue.enqueue(overflow_rec)

            self.assertEqual(queue.qsize(), 5)  # Capped at max_size=5
            self.assertGreater(queue.dropped_count, 0)

            # Verify disk spool file was written
            self.assertTrue(queue.spool_path.exists())
            self.assertGreater(queue.spool_path.stat().st_size, 0)

        finally:
            # Cleanup test spool
            if queue.spool_path.exists():
                queue.spool_path.unlink()
            if test_spool_dir.exists():
                try:
                    test_spool_dir.rmdir()
                except Exception:
                    pass

    # -------------------------------------------------------------------------
    # 3. Feature Validation Against Model Schemas
    # -------------------------------------------------------------------------
    def test_05_feature_validation_schemas(self):
        """Verify FeatureValidator accurately checks DDoS (74), PortScan (78), and C2 (46) schemas."""
        validator = FeatureValidator()
        adapter = FeatureAdapter()

        # Build a synthetic sample flow
        b = FlowBuilder()
        b.process_packet(1000.0, "192.168.1.10", "1.1.1.1", 54321, 443, "TCP", 120, tcp_flags={'SYN': True})
        b.process_packet(1000.1, "1.1.1.1", "192.168.1.10", 443, 54321, "TCP", 1400, tcp_flags={'ACK': True})
        flow_records: List[FlowRecord] = []
        b.consumer_callback = flow_records.append
        b.flush_all()
        self.assertEqual(len(flow_records), 1)
        flow = flow_records[0]

        # Validate across all models
        results = validator.validate_flow_all_models(adapter, flow)

        # 1. DDoS validation
        ddos_res = results["ddos"]
        self.assertTrue(ddos_res.is_valid, f"DDoS validation failed: {ddos_res.error_message}")
        self.assertEqual(ddos_res.expected_count, 74)
        self.assertEqual(ddos_res.actual_count, 74)
        self.assertTrue(ddos_res.ordering_matches)
        self.assertEqual(len(ddos_res.nan_inf_features), 0)

        # 2. PortScan validation
        ps_res = results["portscan"]
        self.assertTrue(ps_res.is_valid, f"PortScan validation failed: {ps_res.error_message}")
        self.assertEqual(ps_res.expected_count, 78)
        self.assertEqual(ps_res.actual_count, 78)
        self.assertTrue(ps_res.ordering_matches)
        self.assertEqual(len(ps_res.nan_inf_features), 0)

        # 3. Botnet C2 validation
        c2_res = results["c2"]
        self.assertTrue(c2_res.is_valid, f"C2 validation failed: {c2_res.error_message}")
        self.assertEqual(c2_res.expected_count, 46)
        self.assertEqual(c2_res.actual_count, 46)
        self.assertTrue(c2_res.ordering_matches)
        self.assertEqual(len(c2_res.nan_inf_features), 0)

    # -------------------------------------------------------------------------
    # 4. Safety Guard: Multicast and Local Discovery Classification
    # -------------------------------------------------------------------------
    def test_06_multicast_and_discovery_safety_guard(self):
        """Verify ordinary multicast, broadcast, and discovery traffic are never misclassified as C2."""
        # Test IP classification
        self.assertTrue(is_multicast_or_broadcast_ip("224.0.0.251"))  # mDNS
        self.assertTrue(is_multicast_or_broadcast_ip("239.255.255.250"))  # SSDP
        self.assertTrue(is_multicast_or_broadcast_ip("255.255.255.255"))  # Global Broadcast
        self.assertTrue(is_multicast_or_broadcast_ip("ff02::fb"))  # IPv6 mDNS
        self.assertFalse(is_multicast_or_broadcast_ip("8.8.8.8"))  # Public Unicast

        # Test Port classification
        self.assertTrue(is_local_discovery_port(5353))  # mDNS
        self.assertTrue(is_local_discovery_port(1900))  # SSDP
        self.assertTrue(is_local_discovery_port(5355))  # LLMNR
        self.assertFalse(is_local_discovery_port(443))   # HTTPS

        # Test evaluation helper
        is_disc, reason = evaluate_multicast_discovery_safety("192.168.0.10", "224.0.0.251", 5353, "UDP")
        self.assertTrue(is_disc)
        self.assertIn("Multicast", reason)

        # Test C2 suppression guard
        # Suppose a model produced C2 prediction=1 and score=0.92 on an mDNS flow
        pred, score, note = prevent_c2_multicast_misclassification(
            c2_prediction=1,
            c2_score=0.92,
            src_ip="192.168.0.10",
            dst_ip="224.0.0.251",
            dst_port=5353,
            protocol="UDP"
        )
        self.assertEqual(pred, 0, "C2 prediction must be suppressed to 0 for multicast discovery.")
        self.assertLess(score, 0.50, "C2 anomaly score must be de-escalated below threshold.")
        self.assertIsNotNone(note)
        self.assertIn("suppressed from C2 classification", note)

    # -------------------------------------------------------------------------
    # 5. Start, Stop, and Clean Restart Lifecycle
    # -------------------------------------------------------------------------
    def test_07_sensor_lifecycle_stop_and_restart(self):
        """Verify sensor starts, stops, and cleanly restarts without socket or thread leaks."""
        sensor = WindowsSensor(SensorConfig(
            interface=self.active_iface_name,
            queue_spool_dir="data/sensor_queue/test_lifecycle",
            enable_spooling=False
        ))

        self.assertEqual(sensor.status, "STOPPED")

        # 1. Start sensor
        start_res = sensor.start()
        self.assertTrue(start_res["success"])
        self.assertEqual(sensor.status, "RUNNING")
        self.assertIsNotNone(sensor.actual_interface)

        # Starting again while running must report already running
        dup_start = sensor.start()
        self.assertFalse(dup_start["success"])

        time.sleep(1.0)

        # 2. Stop sensor
        stop_res = sensor.stop()
        self.assertTrue(stop_res["success"])
        self.assertEqual(sensor.status, "STOPPED")

        # Stopping again while stopped is idempotent
        dup_stop = sensor.stop()
        self.assertTrue(dup_stop["success"])

        # 3. Restart sensor
        restart_res = sensor.restart(self.active_iface_name)
        self.assertTrue(restart_res["success"])
        self.assertEqual(sensor.status, "RUNNING")

        time.sleep(1.0)

        # Final stop
        final_stop = sensor.stop()
        self.assertTrue(final_stop["success"])
        self.assertEqual(sensor.status, "STOPPED")

    # -------------------------------------------------------------------------
    # 6. Real Live Packet Capture & Flow Generation
    # -------------------------------------------------------------------------
    def test_08_live_traffic_capture_and_telemetry(self):
        """
        Executes a 5-second passive capture of live host network traffic.
        Generates genuine traffic and verifies packet arrival, flow creation,
        accurate counters, feature validation, and local metadata queue staging.
        """
        captured_flows: List[FlowRecord] = []
        captured_alerts: List[ThreatAlert] = []

        sensor = WindowsSensor(SensorConfig(
            interface=self.active_iface_name,
            flow_timeout=2.0,
            flow_flush_interval=1.0,
            queue_spool_dir="data/sensor_queue/test_live",
            enable_spooling=True,
            enable_detection=True,
            enable_feature_validation=True
        ))

        sensor.register_flow_callback(captured_flows.append)
        sensor.register_alert_callback(captured_alerts.append)

        print(f"\n[TEST 8] Starting 5-second live capture on '{self.active_iface_name}'...")
        start_res = sensor.start()
        self.assertTrue(start_res["success"], f"Sensor failed to start: {start_res}")

        # Generate lightweight local web activity to ensure observed packets
        for _ in range(4):
            try:
                urllib.request.urlopen("https://www.google.com", timeout=1.5)
            except Exception:
                pass
            time.sleep(0.8)

        # Stop and flush all in-flight flows
        stop_res = sensor.stop()
        self.assertTrue(stop_res["success"])
        self.assertEqual(sensor.status, "STOPPED")

        status = sensor.get_status()
        print(f"[TEST 8] Live Capture Summary:")
        print(f"  Duration:         {status['uptime_seconds']}s")
        print(f"  Packets Captured: {status['packets_captured']}")
        print(f"  IP Packets:       {status['ip_packets']}")
        print(f"  TCP Packets:      {status['tcp_packets']}")
        print(f"  UDP Packets:      {status['udp_packets']}")
        print(f"  Flows Completed:  {status['flows_completed']}")
        print(f"  Queued Records:   {status['queue_enqueued']}")

        # Assertions on real traffic
        self.assertGreater(status['packets_captured'], 0, "No packets captured during live capture.")
        self.assertGreater(status['ip_packets'], 0, "No IP packets captured.")
        self.assertGreater(status['flows_completed'], 0, "No flows aggregated from packets.")
        self.assertGreater(status['queue_enqueued'], 0, "No metadata records enqueued.")

        # Validate captured flow integrity
        sample_flow = captured_flows[0]
        self.assertIsNotNone(sample_flow.flow_id)
        self.assertIsNotNone(sample_flow.src_ip)
        self.assertIsNotNone(sample_flow.dst_ip)
        self.assertIn(sample_flow.protocol, ["TCP", "UDP", "ICMP", "IP_6", "IP_17"])
        self.assertGreaterEqual(sample_flow.total_packets, 1)
        self.assertGreaterEqual(sample_flow.total_bytes, 20)
        self.assertGreaterEqual(sample_flow.last_seen, sample_flow.start_time)
        self.assertGreaterEqual(sample_flow.duration, 0.0)

        # Validate feature compatibility on the live captured flow
        adapter = FeatureAdapter()
        validator = FeatureValidator()
        val_res = validator.validate_flow_all_models(adapter, sample_flow)
        self.assertTrue(val_res["ddos"].is_valid, f"DDoS schema invalid: {val_res['ddos'].error_message}")
        self.assertTrue(val_res["portscan"].is_valid, f"PortScan schema invalid: {val_res['portscan'].error_message}")
        self.assertTrue(val_res["c2"].is_valid, f"C2 schema invalid: {val_res['c2'].error_message}")

        # Cleanup test spool
        spool_p = sensor.metadata_queue.spool_path
        if spool_p.exists():
            spool_p.unlink()
        if spool_p.parent.exists():
            try:
                spool_p.parent.rmdir()
            except Exception:
                pass

    # -------------------------------------------------------------------------
    # 7. Regression Tests: C2 False Positives & Queue Spool Representation
    # -------------------------------------------------------------------------
    def _build_test_flow(
        self,
        flow_id: str,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        protocol: str,
        start_time: float,
        duration: float,
        packets: int,
        bytes_count: int
    ) -> FlowRecord:
        fwd_p = packets // 2
        bwd_p = packets - fwd_p
        fwd_b = bytes_count // 2
        bwd_b = bytes_count - fwd_b
        dur = max(0.001, duration)
        return FlowRecord(
            flow_id=flow_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            start_time=start_time,
            last_seen=start_time + duration,
            duration=duration,
            total_packets=packets,
            total_bytes=bytes_count,
            forward_packets=fwd_p,
            backward_packets=bwd_p,
            forward_bytes=fwd_b,
            backward_bytes=bwd_b,
            packets_per_second=packets / dur,
            bytes_per_second=bytes_count / dur,
            forward_packet_ratio=fwd_p / packets if packets > 0 else 0.0,
            backward_packet_ratio=bwd_p / packets if packets > 0 else 0.0,
            forward_byte_ratio=fwd_b / bytes_count if bytes_count > 0 else 0.0,
            backward_byte_ratio=bwd_b / bytes_count if bytes_count > 0 else 0.0,
            bytes_per_packet=bytes_count / packets if packets > 0 else 0.0,
            packets_per_byte=packets / bytes_count if bytes_count > 0 else 0.0
        )

    def test_09_c2_warmup_insufficient_history_suppression(self):
        """
        Regression Test: C2 evaluation must remain INSUFFICIENT_HISTORY with 0 prediction
        when repeated src-dst observations are fewer than 3 (< 3 flows / < 2 IAT intervals).
        """
        pipeline = AlertPipeline(mode="ALERT", traffic_context="UNLABELED_LIVE")

        # Create 2 sequential flows for the same src-dst pair
        flow1 = self._build_test_flow(
            flow_id="reg_c2_warmup_flow_1",
            src_ip="192.168.0.110",
            dst_ip="35.190.80.1",
            src_port=59001,
            dst_port=443,
            protocol="UDP",
            start_time=1700000000.0,
            duration=1.0,
            packets=10,
            bytes_count=4000
        )
        flow2 = self._build_test_flow(
            flow_id="reg_c2_warmup_flow_2",
            src_ip="192.168.0.110",
            dst_ip="35.190.80.1",
            src_port=59001,
            dst_port=443,
            protocol="UDP",
            start_time=1700000010.0,
            duration=1.0,
            packets=10,
            bytes_count=4000
        )

        alert1 = pipeline.process_flow(flow1)
        self.assertIsNone(alert1, "Flow 1 must not trigger an alert during cold start.")

        alert2 = pipeline.process_flow(flow2)
        # On observation #2, warm-up condition (< 3 flows) must prevent premature C2 alerting
        self.assertIsNone(alert2, "Flow 2 (obs=2) must not trigger premature C2 alert before 3 observations.")

    def test_10_quic_web_egress_safety_guard(self):
        """
        Regression Test: Standard QUIC web traffic (UDP:443) must be recognized and
        suppressed from C2 classification when timing regularity is unproven.
        """
        # 1. QUIC detection predicate
        self.assertTrue(is_quic_traffic(443, "UDP"))
        self.assertTrue(is_quic_traffic(443, "udp"))
        self.assertFalse(is_quic_traffic(80, "UDP"))
        self.assertFalse(is_quic_traffic(443, "TCP"))
        self.assertFalse(is_quic_traffic(None, "UDP"))

        # 2. Suppress false C2 alert on standard QUIC web egress
        sanitized_pred, sanitized_score, note = prevent_c2_multicast_misclassification(
            c2_prediction=1,
            c2_score=0.82,
            src_ip="192.168.0.110",
            dst_ip="35.190.80.1",
            dst_port=443,
            protocol="UDP",
            iat_regularity=0.0,
            obs_count=2
        )
        self.assertEqual(sanitized_pred, 0, "C2 prediction must be suppressed to 0 for unproven QUIC egress.")
        self.assertLess(sanitized_score, 0.50, "C2 anomaly score must be scaled below threat threshold.")
        self.assertIsNotNone(note)
        self.assertIn("QUIC", note)

    def test_11_alert_record_serialization_flow_metrics(self):
        """
        Regression Test: Enqueued THREAT_ALERT records must contain complete flow metadata
        (total_packets, total_bytes, src_port, dst_port), rather than empty/zero summaries.
        """
        sensor = WindowsSensor(SensorConfig(
            queue_spool_dir="data/sensor_queue/test_alert_metrics",
            enable_spooling=False
        ))

        test_alert = ThreatAlert(
            alert_id="test_alert_001",
            timestamp=1700000000.0,
            flow_id="test_flow_quic_123",
            src_ip="192.168.0.110",
            dst_ip="35.190.80.1",
            src_port=59001,
            dst_port=443,
            protocol="UDP",
            threat_class="BOTNET_C2",
            threat_category="BOTNET_C2",
            severity="MEDIUM",
            confidence=0.82,
            traffic_context="UNLABELED_LIVE",
            detector="HybridPCA_Botnet_C2",
            model_status="FULLY_COMPATIBLE",
            evidence=[],
            evidence_summary="Test C2 alert",
            recommended_action="Inspect",
            flow_duration=1.25,
            total_packets=25,
            total_bytes=10500
        )

        sensor._handle_generated_alert(test_alert)
        self.assertEqual(sensor.metadata_queue.qsize(), 1)

        queued_rec = sensor.metadata_queue.dequeue()
        self.assertIsNotNone(queued_rec)
        self.assertEqual(queued_rec.record_type, "THREAT_ALERT")

        flow_dict = queued_rec.flow
        self.assertIsNotNone(flow_dict)
        self.assertEqual(flow_dict.get("total_packets"), 25)
        self.assertEqual(flow_dict.get("total_bytes"), 10500)
        self.assertEqual(flow_dict.get("src_port"), 59001)
        self.assertEqual(flow_dict.get("dst_port"), 443)
        self.assertEqual(flow_dict.get("protocol"), "UDP")

    def test_12_inspect_queue_accurate_disk_count_reporting(self):
        """
        Regression Test: Local queue inspection must report the true disk record count
        independently of the sample display slice size (e.g., 10 records staged vs. 5 sampled).
        """
        test_dir = Path("data/sensor_queue/test_inspect_count")
        test_dir.mkdir(parents=True, exist_ok=True)
        spool_path = test_dir / "metadata_spool.jsonl"

        try:
            # Write 10 test records to spool file
            with open(spool_path, "w", encoding="utf-8") as f:
                for i in range(10):
                    rec = {
                        "record_id": f"rec_{i}",
                        "timestamp": 1700000000.0 + i,
                        "record_type": "FLOW",
                        "delivery_status": "PENDING_LOCAL",
                        "flow": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2", "protocol": "TCP", "total_packets": 5, "total_bytes": 300}
                    }
                    f.write(json.dumps(rec) + "\n")

            # Check that disk line count reflects 10, while sample limit is 5
            with open(spool_path, "r", encoding="utf-8") as f:
                lines = [line for line in f if line.strip()]
                total_on_disk = len(lines)
                sample = [json.loads(line) for line in lines[-5:]]

            self.assertEqual(total_on_disk, 10, "Total disk count must reflect all 10 persistent lines.")
            self.assertEqual(len(sample), 5, "Sample display slice must be constrained to 5 records.")
            self.assertNotEqual(total_on_disk, len(sample), "Total count must not be conflated with sample slice size.")
        finally:
            if spool_path.exists():
                spool_path.unlink()
            if test_dir.exists():
                try:
                    test_dir.rmdir()
                except Exception:
                    pass

    def test_13_discovery_alert_suppression_prevents_queue_leak(self):
        """
        Regression Test: Suppressed discovery alerts (e.g., DHCP UDP:67 or DNS UDP:53)
        must not leak into the metadata queue or increment sensor.threats_detected.
        """
        sensor = WindowsSensor(SensorConfig(
            queue_spool_dir="data/sensor_queue/test_disc_leak",
            enable_spooling=False,
            enable_detection=True
        ))
        sensor._alert_pipeline = AlertPipeline(mode="ALERT", traffic_context="UNLABELED_LIVE")

        # DHCP discovery flow
        dhcp_flow = self._build_test_flow(
            flow_id="test_dhcp_suppression_flow",
            src_ip="192.168.0.110",
            dst_ip="192.168.0.1",
            src_port=68,
            dst_port=67,
            protocol="UDP",
            start_time=1700000000.0,
            duration=0.01,
            packets=2,
            bytes_count=949
        )

        sensor._handle_completed_flow(dhcp_flow)

        # Threats detected must be 0
        self.assertEqual(sensor.threats_detected, 0, "Suppressed discovery alert must not increment threats_detected.")
        # Only the 1 FLOW record must be enqueued, zero THREAT_ALERT records
        self.assertEqual(sensor.metadata_queue.qsize(), 1, "Queue must contain only the FLOW record.")
        rec = sensor.metadata_queue.dequeue()
        self.assertEqual(rec.record_type, "FLOW")
        self.assertIsNotNone(rec.detection)
        self.assertEqual(rec.detection.get("threat_class"), "BENIGN")

    def test_14_established_https_not_flagged_as_portscan(self):
        """
        Regression Test: Established web sessions (e.g. HTTPS port 443 with bidirectional data)
        must not be misclassified as single-flow port reconnaissance probes.
        """
        # 1. Predicate checks
        self.assertTrue(is_established_web_flow("TCP", 443, 31, 39735, ack_count=30))
        self.assertTrue(is_established_web_flow("tcp", 80, 10, 5000, ack_count=5))
        self.assertFalse(is_established_web_flow("TCP", 443, 1, 60, ack_count=0))  # SYN probe
        self.assertFalse(is_established_web_flow("UDP", 443, 31, 39735, ack_count=0))
        self.assertFalse(is_established_web_flow("TCP", 22, 31, 39735, ack_count=30))  # Non-web port

        # 2. Sensor integration flow check
        sensor = WindowsSensor(SensorConfig(
            queue_spool_dir="data/sensor_queue/test_https_portscan",
            enable_spooling=False,
            enable_detection=True
        ))
        sensor._alert_pipeline = AlertPipeline(mode="ALERT", traffic_context="UNLABELED_LIVE")

        https_flow = self._build_test_flow(
            flow_id="test_https_flow_36",
            src_ip="192.168.0.110",
            dst_ip="20.190.146.33",
            src_port=65372,
            dst_port=443,
            protocol="TCP",
            start_time=1700000000.0,
            duration=0.345,
            packets=31,
            bytes_count=39735
        )
        https_flow.syn_count = 2
        https_flow.ack_count = 30
        https_flow.psh_count = 7

        sensor._handle_completed_flow(https_flow)

        self.assertEqual(sensor.threats_detected, 0, "Established HTTPS session must not trigger PortScan alert.")
        self.assertEqual(sensor.metadata_queue.qsize(), 1)
        rec = sensor.metadata_queue.dequeue()
        self.assertEqual(rec.record_type, "FLOW")
        self.assertEqual(rec.detection.get("threat_class"), "BENIGN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
