"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.test_flow_builder

Unit tests for FlowBuilder and bidirectional connection aggregation.
Uses in-memory synthetic packet metadata ONLY (Zero network transmission).
"""

import sys
import time
import unittest
from pathlib import Path
from typing import List

# Ensure root directory is on path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from src.capture.flow_builder import FlowBuilder
from src.capture.flow_schema import FlowRecord


class TestFlowBuilder(unittest.TestCase):
    """Test suite for FlowBuilder state machine and feature calculation."""

    def test_01_flow_creation_and_forward_packets(self):
        """Test initial forward packet creating a flow and subsequent forward packets updating counters."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=5.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 1000.0
        # Packet 1: Forward SYN packet (Client -> Server)
        builder.process_packet(
            timestamp=t0,
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            byte_len=60,
            tcp_flags={'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )

        self.assertEqual(builder.active_flow_count, 1)

        # Packet 2: Forward data packet 0.5s later (Client -> Server)
        builder.process_packet(
            timestamp=t0 + 0.5,
            src_ip="192.168.1.10",
            dst_ip="93.184.216.34",
            src_port=54321,
            dst_port=443,
            protocol="TCP",
            byte_len=500,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )

        self.assertEqual(builder.active_flow_count, 1)

        # Flush flow
        builder.flush_all()
        self.assertEqual(len(emitted_flows), 1)

        record = emitted_flows[0]
        self.assertEqual(record.src_ip, "192.168.1.10")
        self.assertEqual(record.dst_ip, "93.184.216.34")
        self.assertEqual(record.src_port, 54321)
        self.assertEqual(record.dst_port, 443)
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual(record.total_packets, 2)
        self.assertEqual(record.forward_packets, 2)
        self.assertEqual(record.backward_packets, 0)
        self.assertEqual(record.total_bytes, 560)
        self.assertEqual(record.forward_bytes, 560)
        self.assertEqual(record.backward_bytes, 0)
        self.assertEqual(record.syn_count, 1)
        self.assertEqual(record.psh_count, 1)
        self.assertAlmostEqual(record.duration, 0.5, places=4)

    def test_02_bidirectional_flow_aggregation(self):
        """Test that reverse packets (Server -> Client) are mapped to the same bidirectional flow."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=5.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 2000.0
        # Forward: Client -> Server (SYN)
        builder.process_packet(
            timestamp=t0,
            src_ip="10.0.0.5",
            dst_ip="104.244.42.1",
            src_port=60000,
            dst_port=80,
            protocol="TCP",
            byte_len=64,
            tcp_flags={'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )

        # Backward: Server -> Client (SYN-ACK)
        builder.process_packet(
            timestamp=t0 + 0.05,
            src_ip="104.244.42.1",
            dst_ip="10.0.0.5",
            src_port=80,
            dst_port=60000,
            protocol="TCP",
            byte_len=64,
            tcp_flags={'SYN': True, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )

        # Forward: Client -> Server (ACK)
        builder.process_packet(
            timestamp=t0 + 0.10,
            src_ip="10.0.0.5",
            dst_ip="104.244.42.1",
            src_port=60000,
            dst_port=80,
            protocol="TCP",
            byte_len=52,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )

        # Backward: Server -> Client (Response Data)
        builder.process_packet(
            timestamp=t0 + 0.20,
            src_ip="104.244.42.1",
            dst_ip="10.0.0.5",
            src_port=80,
            dst_port=60000,
            protocol="TCP",
            byte_len=1400,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )

        # Still exactly 1 active flow in memory
        self.assertEqual(builder.active_flow_count, 1)

        builder.flush_all()
        self.assertEqual(len(emitted_flows), 1)

        record = emitted_flows[0]
        self.assertEqual(record.total_packets, 4)
        self.assertEqual(record.forward_packets, 2)
        self.assertEqual(record.backward_packets, 2)
        self.assertEqual(record.forward_bytes, 116)
        self.assertEqual(record.backward_bytes, 1464)
        self.assertEqual(record.total_bytes, 1580)
        self.assertEqual(record.syn_count, 2)
        self.assertEqual(record.ack_count, 3)
        self.assertEqual(record.psh_count, 1)
        self.assertAlmostEqual(record.duration, 0.20, places=4)
        self.assertAlmostEqual(record.forward_packet_ratio, 0.5)
        self.assertAlmostEqual(record.backward_packet_ratio, 0.5)

    def test_03_flow_timeout_and_expiration(self):
        """Test that inactive flows are automatically evicted and finalized when timeout threshold is exceeded."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=2.0,
            flush_interval_seconds=1.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 3000.0
        # Flow 1 (t=3000)
        builder.process_packet(
            timestamp=t0,
            src_ip="192.168.0.50",
            dst_ip="8.8.8.8",
            src_port=49152,
            dst_port=53,
            protocol="UDP",
            byte_len=75
        )

        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # Flow 2 arrives at t=3003 (3.0s later -> Flow 1 has timed out)
        builder.process_packet(
            timestamp=t0 + 3.0,
            src_ip="192.168.0.50",
            dst_ip="1.1.1.1",
            src_port=49153,
            dst_port=53,
            protocol="UDP",
            byte_len=80
        )

        # Flow 1 should have been evicted and emitted during the periodic flush
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].dst_ip, "8.8.8.8")
        self.assertEqual(builder.active_flow_count, 1)

        # Flush remaining Flow 2
        builder.flush_all()
        self.assertEqual(len(emitted_flows), 2)
        self.assertEqual(emitted_flows[1].dst_ip, "1.1.1.1")
        self.assertEqual(builder.active_flow_count, 0)

    def test_04_safe_derived_features(self):
        """Test that single-packet zero-duration flows compute all rates and ratios without producing NaN or Inf."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=5.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        # Single ICMP probe (duration = 0.0)
        builder.process_packet(
            timestamp=4000.0,
            src_ip="10.10.10.10",
            dst_ip="10.10.10.1",
            src_port=None,
            dst_port=None,
            protocol="ICMP",
            byte_len=84
        )

        builder.flush_all()
        self.assertEqual(len(emitted_flows), 1)

        record = emitted_flows[0]
        self.assertEqual(record.duration, 0.0)
        self.assertEqual(record.packets_per_second, 1.0)
        self.assertEqual(record.bytes_per_second, 84.0)
        self.assertEqual(record.forward_packet_ratio, 1.0)
        self.assertEqual(record.backward_packet_ratio, 0.0)
        self.assertEqual(record.bytes_per_packet, 84.0)
        self.assertEqual(record.packets_per_byte, 1.0 / 84.0)

        # Test JSON serialization produces valid string
        json_str = record.to_json()
        self.assertIn('"protocol": "ICMP"', json_str)
        self.assertIn('"bytes_per_packet": 84.0', json_str)

    def test_05_tcp_rst_immediate_finalization(self):
        """Test that a TCP flow is immediately finalized and emitted upon observing a RST flag."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=30.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 5000.0
        # Packet 1: SYN
        builder.process_packet(
            timestamp=t0,
            src_ip="192.168.1.50",
            dst_ip="203.0.113.10",
            src_port=50001,
            dst_port=443,
            protocol="TCP",
            byte_len=60,
            tcp_flags={'SYN': True, 'ACK': False, 'FIN': False, 'RST': False, 'PSH': False, 'URG': False}
        )
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # Packet 2: RST abort
        builder.process_packet(
            timestamp=t0 + 0.1,
            src_ip="203.0.113.10",
            dst_ip="192.168.1.50",
            src_port=443,
            dst_port=50001,
            protocol="TCP",
            byte_len=40,
            tcp_flags={'SYN': False, 'ACK': False, 'FIN': False, 'RST': True, 'PSH': False, 'URG': False}
        )

        # Should be finalized immediately without waiting for timeout
        self.assertEqual(builder.active_flow_count, 0)
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].rst_count, 1)
        self.assertEqual(emitted_flows[0].total_packets, 2)

    def test_06_tcp_mutual_fin_immediate_finalization(self):
        """Test that a TCP flow is immediately finalized when both endpoints send FIN."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=30.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 6000.0
        # Packet 1: Client data
        builder.process_packet(
            timestamp=t0,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=40000,
            dst_port=80,
            protocol="TCP",
            byte_len=200,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )
        # Packet 2: Client FIN
        builder.process_packet(
            timestamp=t0 + 0.05,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=40000,
            dst_port=80,
            protocol="TCP",
            byte_len=54,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': True, 'RST': False, 'PSH': False, 'URG': False}
        )
        # Still active (fin_count = 1)
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # Packet 3: Server FIN-ACK (mutual FIN reached)
        builder.process_packet(
            timestamp=t0 + 0.1,
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            src_port=80,
            dst_port=40000,
            protocol="TCP",
            byte_len=54,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': True, 'RST': False, 'PSH': False, 'URG': False}
        )

        # Immediately finalized on mutual FIN
        self.assertEqual(builder.active_flow_count, 0)
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].fin_count, 2)

    def test_07_tcp_single_fin_teardown_timeout(self):
        """Test that a TCP flow with single FIN uses the 2.0s teardown timeout instead of full timeout."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=30.0,
            flush_interval_seconds=1.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 7000.0
        # Packet with single FIN
        builder.process_packet(
            timestamp=t0,
            src_ip="10.0.0.2",
            dst_ip="10.0.0.1",
            src_port=45000,
            dst_port=80,
            protocol="TCP",
            byte_len=60,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': True, 'RST': False, 'PSH': False, 'URG': False}
        )
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # At t0 + 1.0s, teardown timeout (2.0s) has NOT expired
        builder.flush_expired(t0 + 1.0)
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # At t0 + 2.5s, teardown timeout (2.0s) has expired (well before 30.0s global timeout)
        builder.flush_expired(t0 + 2.5)
        self.assertEqual(builder.active_flow_count, 0)
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].fin_count, 1)

    def test_08_udp_fast_inactivity_timeout(self):
        """Test that UDP flows (e.g. DNS) expire after udp_timeout_seconds (3.0s) without waiting for 30s."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=30.0,
            udp_timeout_seconds=3.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 8000.0
        # DNS Query
        builder.process_packet(
            timestamp=t0,
            src_ip="192.168.0.100",
            dst_ip="8.8.8.8",
            src_port=53535,
            dst_port=53,
            protocol="UDP",
            byte_len=68
        )
        # DNS Response
        builder.process_packet(
            timestamp=t0 + 0.02,
            src_ip="8.8.8.8",
            dst_ip="192.168.0.100",
            src_port=53,
            dst_port=53535,
            protocol="UDP",
            byte_len=142
        )
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # At t0 + 2.0s, UDP timeout (3.0s) has not expired
        builder.flush_expired(t0 + 2.0)
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # At t0 + 3.5s, UDP timeout has expired
        builder.flush_expired(t0 + 3.5)
        self.assertEqual(builder.active_flow_count, 0)
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].protocol, "UDP")
        self.assertEqual(emitted_flows[0].total_packets, 2)

    def test_09_tcp_bidirectional_idle_timeout(self):
        """Test that completed bidirectional TCP transactions without FIN expire after tcp_idle_timeout_seconds (10.0s)."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=30.0,
            tcp_idle_timeout_seconds=10.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 9000.0
        # Forward data
        builder.process_packet(
            timestamp=t0,
            src_ip="192.168.0.100",
            dst_ip="104.18.40.40",
            src_port=62000,
            dst_port=443,
            protocol="TCP",
            byte_len=200,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )
        # Backward data
        builder.process_packet(
            timestamp=t0 + 0.1,
            src_ip="104.18.40.40",
            dst_ip="192.168.0.100",
            src_port=443,
            dst_port=62000,
            protocol="TCP",
            byte_len=1200,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )
        self.assertEqual(builder.active_flow_count, 1)

        # At t0 + 5.0s, idle timeout has not expired
        builder.flush_expired(t0 + 5.0)
        self.assertEqual(builder.active_flow_count, 1)
        self.assertEqual(len(emitted_flows), 0)

        # At t0 + 10.5s, completed TCP transaction is finalized (long before 30s global timeout)
        builder.flush_expired(t0 + 10.5)
        self.assertEqual(builder.active_flow_count, 0)
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].forward_packets, 1)
        self.assertEqual(emitted_flows[0].backward_packets, 1)

    def test_10_active_timeout_flow_slicing(self):
        """Test that long-running active connections slice and emit flows every active_timeout_seconds (15.0s)."""
        emitted_flows: List[FlowRecord] = []
        builder = FlowBuilder(
            timeout_seconds=30.0,
            active_timeout_seconds=15.0,
            consumer_callback=lambda f: emitted_flows.append(f)
        )

        t0 = 10000.0
        # Continuous streaming: packets every 1.0s for 16 seconds
        for i in range(16):
            builder.process_packet(
                timestamp=t0 + float(i),
                src_ip="192.168.0.100",
                dst_ip="172.217.115.4",
                src_port=55555,
                dst_port=443,
                protocol="TCP",
                byte_len=1000,
                tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
            )

        # At t0 + 15.5s, active timeout (15.0s) triggers flow slicing
        builder.flush_expired(t0 + 15.5)
        self.assertEqual(len(emitted_flows), 1)
        self.assertEqual(emitted_flows[0].total_packets, 16)
        slice1_id = emitted_flows[0].flow_id

        # New packet on the same connection starts slice 2
        builder.process_packet(
            timestamp=t0 + 16.0,
            src_ip="192.168.0.100",
            dst_ip="172.217.115.4",
            src_port=55555,
            dst_port=443,
            protocol="TCP",
            byte_len=1000,
            tcp_flags={'SYN': False, 'ACK': True, 'FIN': False, 'RST': False, 'PSH': True, 'URG': False}
        )
        self.assertEqual(builder.active_flow_count, 1)
        builder.flush_all()
        self.assertEqual(len(emitted_flows), 2)
        slice2_id = emitted_flows[1].flow_id

        # Slices have unique deterministic IDs
        self.assertNotEqual(slice1_id, slice2_id)


if __name__ == '__main__':
    unittest.main(verbosity=2)
