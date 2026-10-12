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


if __name__ == '__main__':
    unittest.main(verbosity=2)
