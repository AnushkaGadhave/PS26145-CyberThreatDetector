"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.test_live_dashboard_pipeline

Focused regression test exercising the dashboard capture pipeline:
Start Monitoring -> capture worker -> packet callback -> FlowBuilder -> flow finalization ->
event pipeline -> /api/capture/events -> response parsing matching frontend LiveStreamEventItem.
Uses purely synthetic in-memory packets (Zero network transmission).
"""

import sys
import time
import unittest
from pathlib import Path
from typing import List, Dict, Any
from unittest.mock import patch, MagicMock

# Ensure project root is in sys.path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from fastapi.testclient import TestClient
from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from src.api.main import app
from src.auth.dependencies import get_current_user, require_admin
from src.database.models import UserModel
from src.capture.capture_service import LiveCaptureManager, capture_manager
from src.capture.live_capture import extract_packet_metadata
from src.capture.flow_schema import FlowRecord


class MockAdminUser:
    """Mock authenticated administrator for API test endpoints."""
    user_id = "admin-uuid-test"
    email = "admin@soc.gov.in"
    full_name = "Chief Security Officer"
    role = "admin"
    is_active = True


class TestLiveDashboardPipeline(unittest.TestCase):
    """Focused regression test for dashboard live monitor capture and streaming pipeline."""

    @classmethod
    def setUpClass(cls):
        # Override auth dependencies to simulate an authenticated local administrator
        app.dependency_overrides[get_current_user] = lambda: MockAdminUser()
        app.dependency_overrides[require_admin] = lambda: MockAdminUser()
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        app.dependency_overrides.clear()
        if capture_manager.status == "RUNNING":
            capture_manager.stop()

    def setUp(self):
        # Clean capture_manager state
        capture_manager.status = "STOPPED"
        capture_manager.recent_events.clear()
        capture_manager.total_packets = 0
        capture_manager.flows_completed = 0
        capture_manager.alerts_generated = 0

    def test_01_synthetic_packet_metadata_extraction(self):
        """1. Verify that raw synthetic packets are parsed into required metadata without payload retention."""
        tcp_pkt = IP(src="192.168.0.110", dst="104.16.80.73") / TCP(sport=54321, dport=443, flags="PA") / b"SIMULATED_TLS"
        meta = extract_packet_metadata(tcp_pkt)

        self.assertIsNotNone(meta)
        self.assertEqual(meta["src_ip"], "192.168.0.110")
        self.assertEqual(meta["dst_ip"], "104.16.80.73")
        self.assertEqual(meta["src_port"], 54321)
        self.assertEqual(meta["dst_port"], 443)
        self.assertEqual(meta["protocol"], "TCP")
        self.assertTrue(meta["tcp_flags"]["PSH"])
        self.assertTrue(meta["tcp_flags"]["ACK"])
        self.assertFalse(meta["tcp_flags"]["SYN"])
        # Payload bytes are NOT in metadata
        self.assertNotIn("payload", meta)
        self.assertNotIn("SIMULATED_TLS", str(meta))

    def test_02_packet_reaches_flow_builder_and_finalizes_on_timeout(self):
        """2. Verify that packets feed FlowBuilder and finalize deterministically via protocol-specific timeouts."""
        emitted: List[FlowRecord] = []
        cm = LiveCaptureManager()
        cm.start_time = time.time()
        cm.status = "RUNNING"

        # Direct flow builder check
        from src.capture.flow_builder import FlowBuilder
        builder = FlowBuilder(
            timeout_seconds=30.0,
            udp_timeout_seconds=3.0,
            tcp_idle_timeout_seconds=10.0,
            active_timeout_seconds=15.0,
            consumer_callback=lambda f: emitted.append(f)
        )

        t0 = 100000.0
        # Send UDP DNS query and response
        builder.process_packet(
            timestamp=t0,
            src_ip="192.168.0.110",
            dst_ip="1.1.1.1",
            src_port=52000,
            dst_port=53,
            protocol="UDP",
            byte_len=70
        )
        builder.process_packet(
            timestamp=t0 + 0.015,
            src_ip="1.1.1.1",
            dst_ip="192.168.0.110",
            src_port=53,
            dst_port=52000,
            protocol="UDP",
            byte_len=140
        )

        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted), 0)

        # Flush at t0 + 3.1s -> UDP timeout (3.0s) should finalize flow promptly
        builder.flush_expired(t0 + 3.1)
        self.assertEqual(builder.active_flow_count, 0)
        self.assertEqual(len(emitted), 1)
        record = emitted[0]
        self.assertEqual(record.protocol, "UDP")
        self.assertEqual(record.total_packets, 2)
        self.assertEqual(record.total_bytes, 210)
        self.assertAlmostEqual(record.duration, 0.015, places=4)

    def test_03_integrated_dashboard_event_pipeline_and_api_schema(self):
        """
        3. End-to-end integration test:
           Feed synthetic packets into capture manager callback,
           finalize flow, verify it populates recent_events,
           and verify GET /api/capture/events returns schema matching frontend LiveStreamEventItem.
        """
        cm = capture_manager
        # Simulate manager initialized and running
        cm.status = "RUNNING"
        cm.start_time = time.time()
        cm.actual_interface = "Wi-Fi 2"
        cm.interface = "Wi-Fi 2"
        cm.recent_events.clear()
        cm.total_packets = 0
        cm.flows_completed = 0

        from src.capture.flow_builder import FlowBuilder
        from src.alerts.alert_pipeline import AlertPipeline

        cm._builder = FlowBuilder(
            timeout_seconds=30.0,
            flush_interval_seconds=1.0,
            udp_timeout_seconds=3.0,
            tcp_idle_timeout_seconds=10.0,
            active_timeout_seconds=15.0,
            consumer_callback=cm._on_flow_built
        )
        cm._alert_pipeline = AlertPipeline(
            mode="ALERT",
            traffic_context="UNLABELED_LIVE",
            suppression_seconds=15.0,
            jsonl_path=None,
            csv_path=None
        )

        t_now = time.time()
        # Feed synthetic TCP web browsing flow (SYN, ACK, DATA, FIN-ACK)
        cm._builder.process_packet(
            timestamp=t_now,
            src_ip="192.168.0.110",
            dst_ip="93.184.216.34",
            src_port=51234,
            dst_port=443,
            protocol="TCP",
            byte_len=60,
            tcp_flags={'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )
        cm.total_packets += 1

        cm._builder.process_packet(
            timestamp=t_now + 0.05,
            src_ip="93.184.216.34",
            dst_ip="192.168.0.110",
            src_port=443,
            dst_port=51234,
            protocol="TCP",
            byte_len=1200,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )
        cm.total_packets += 1

        # Feed mutual FIN teardown
        cm._builder.process_packet(
            timestamp=t_now + 0.10,
            src_ip="192.168.0.110",
            dst_ip="93.184.216.34",
            src_port=51234,
            dst_port=443,
            protocol="TCP",
            byte_len=54,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': True, 'RST': False, 'PSH': False, 'URG': False}
        )
        cm.total_packets += 1

        cm._builder.process_packet(
            timestamp=t_now + 0.12,
            src_ip="93.184.216.34",
            dst_ip="192.168.0.110",
            src_port=443,
            dst_port=51234,
            protocol="TCP",
            byte_len=54,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': True, 'RST': False, 'PSH': False, 'URG': False}
        )
        cm.total_packets += 1

        # Because mutual FIN was observed, flow was finalized immediately!
        self.assertEqual(cm.flows_completed, 1)
        self.assertEqual(len(cm.recent_events), 1)

        # 4. Query GET /api/capture/events
        res = self.client.get("/api/capture/events?limit=30")
        self.assertEqual(res.status_code, 200)
        events = res.json()
        self.assertIsInstance(events, list)
        self.assertEqual(len(events), 1)

        evt = events[0]
        # Validate exact schema expected by frontend LiveStreamEventItem in api.ts
        expected_fields = [
            "id", "timestamp", "flow_id", "src_ip", "dst_ip", "dst_port",
            "protocol", "packets", "bytes", "duration", "threat_outcome", "severity"
        ]
        for field in expected_fields:
            self.assertIn(field, evt, f"Missing field '{field}' in live stream event schema")

        self.assertEqual(evt["src_ip"], "192.168.0.110")
        self.assertEqual(evt["dst_ip"], "93.184.216.34")
        self.assertEqual(evt["dst_port"], 443)
        self.assertEqual(evt["protocol"], "TCP")
        self.assertEqual(evt["packets"], 4)
        self.assertEqual(evt["bytes"], 1368)
        self.assertIsInstance(evt["timestamp"], int)
        # Timestamp must be in milliseconds (>= 1e11)
        self.assertGreater(evt["timestamp"], 1e11)

        # 5. Query GET /api/capture/status
        st_res = self.client.get("/api/capture/status")
        self.assertEqual(st_res.status_code, 200)
        status_data = st_res.json()
        self.assertEqual(status_data["state"], "ACTIVE")
        self.assertEqual(status_data["interface"], "Wi-Fi 2")
        self.assertGreaterEqual(status_data["packets_captured"], 4)
        self.assertEqual(status_data["flows_created"], 1)

    def test_04_active_slicing_emits_ongoing_stream(self):
        """4. Verify that ongoing streams without FIN are sliced and emitted to recent_events at active_timeout."""
        cm = capture_manager
        cm.status = "RUNNING"
        cm.start_time = time.time()
        cm.recent_events.clear()
        cm.flows_completed = 0

        from src.capture.flow_builder import FlowBuilder
        cm._builder = FlowBuilder(
            timeout_seconds=30.0,
            active_timeout_seconds=15.0,
            consumer_callback=cm._on_flow_built
        )

        t0 = 200000.0
        # Active streaming: 10 packets over 16 seconds
        for i in range(16):
            cm._builder.process_packet(
                timestamp=t0 + float(i),
                src_ip="192.168.0.110",
                dst_ip="172.217.115.4",
                src_port=56000,
                dst_port=443,
                protocol="TCP",
                byte_len=1400,
                tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
            )

        # At t0 + 15.5s, active timeout slice triggers
        cm._builder.flush_expired(t0 + 15.5)

        # Event was emitted to recent_events while connection continues
        self.assertEqual(cm.flows_completed, 1)
        self.assertEqual(len(cm.recent_events), 1)

        evt = cm.get_recent_events()[0]
        self.assertEqual(evt["src_ip"], "192.168.0.110")
        self.assertEqual(evt["dst_ip"], "172.217.115.4")
        self.assertEqual(evt["packets"], 16)
        self.assertGreaterEqual(evt["duration"], 14.0)

    def test_05_capture_controls_start_stop_restart_lifecycle(self):
        """5. Verify capture worker start, stop, restart and double-start safety."""
        cm = capture_manager
        with patch.object(cm, "_capture_worker_loop", return_value=None):
            # 1. Start capture
            res1 = cm.start("Wi-Fi 2")
            self.assertTrue(res1["success"])
            self.assertEqual(cm.status, "RUNNING")

            # 2. Double-start rejected gracefully
            res2 = cm.start("Wi-Fi 2")
            self.assertFalse(res2["success"])
            self.assertIn("already", res2["message"].lower())

            # 3. Stop capture
            res3 = cm.stop()
            self.assertTrue(res3["success"])
            self.assertEqual(cm.status, "STOPPED")

            # 4. Double-stop handled cleanly
            res4 = cm.stop()
            self.assertTrue(res4["success"])
            self.assertEqual(cm.status, "STOPPED")

    def test_06_concurrent_packet_processing_and_flush_expired_safety(self):
        """6. Verify concurrent packet ingestion and periodic flushing do not corrupt active flow state."""
        import threading
        from src.capture.flow_builder import FlowBuilder

        emitted: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=5.0,
            flush_interval_seconds=0.1,
            consumer_callback=lambda f: emitted.append(f)
        )

        def worker_feed(tid: int):
            for i in range(20):
                builder.process_packet(
                    timestamp=1000.0 + (i * 0.05),
                    src_ip=f"192.168.1.{tid}",
                    dst_ip="93.184.216.34",
                    src_port=50000 + tid,
                    dst_port=443,
                    protocol="TCP",
                    byte_len=100 + i,
                    tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
                )

        def worker_flush():
            for i in range(10):
                builder.flush_expired(1001.0 + (i * 0.1))

        threads = [
            threading.Thread(target=worker_feed, args=(1,)),
            threading.Thread(target=worker_feed, args=(2,)),
            threading.Thread(target=worker_flush)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        builder.flush_all()
        # Ensure flows from both threads were created and finalized without deadlock or memory corruption
        self.assertGreaterEqual(len(emitted), 2)
        self.assertEqual(builder.active_flow_count, 0)

    def test_07_c2_inbound_web_flow_deescalation_in_pipeline(self):
        """7. Verify inbound HTTPS traffic (104.18.39.21:443 -> laptop) is evaluated as BENIGN in capture pipeline."""
        cm = capture_manager
        cm.status = "RUNNING"
        cm.start_time = time.time()
        cm.recent_events.clear()
        cm.flows_completed = 0

        from src.capture.flow_builder import FlowBuilder
        from src.alerts.alert_pipeline import AlertPipeline

        cm._builder = FlowBuilder(
            timeout_seconds=30.0,
            tcp_idle_timeout_seconds=10.0,
            consumer_callback=cm._on_flow_built
        )
        cm._alert_pipeline = AlertPipeline(
            mode="ALERT",
            traffic_context="UNLABELED_LIVE",
            suppression_seconds=15.0,
            jsonl_path=None,
            csv_path=None
        )

        t_now = time.time()
        # Inbound-first Cloudflare CDN flow (6 pkts, 428 bytes, port 443 -> 59762)
        cm._builder.process_packet(
            timestamp=t_now,
            src_ip="104.18.39.21",
            dst_ip="192.168.0.110",
            src_port=443,
            dst_port=59762,
            protocol="TCP",
            byte_len=60,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )
        cm._builder.process_packet(
            timestamp=t_now + 0.05,
            src_ip="192.168.0.110",
            dst_ip="104.18.39.21",
            src_port=59762,
            dst_port=443,
            protocol="TCP",
            byte_len=368,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )

        # Finalize via idle timeout
        cm._builder.flush_expired(t_now + 10.5)

        self.assertEqual(cm.flows_completed, 1)
        self.assertEqual(len(cm.recent_events), 1)

        evt = cm.get_recent_events()[0]
        # Must be BENIGN, not false-positive BOTNET_C2
        self.assertEqual(evt["threat_outcome"], "BENIGN")
        self.assertEqual(evt["severity"], "BENIGN")


if __name__ == "__main__":
    unittest.main(verbosity=2)
