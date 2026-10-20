"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.test_live_capture

Unit and integration tests for Scapy Npcap packet capture engine.
Tests interface discovery, Wi-Fi 2 adapter status, and short passive sniffing.
"""

import sys
import unittest
from pathlib import Path

# Ensure root directory is on path
project_root = Path(__file__).resolve().parent.parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

import scapy.all as scapy
from scapy.arch.windows import get_windows_if_list
from src.capture.live_capture import capture_packets, DEFAULT_INTERFACE


class TestLiveCapture(unittest.TestCase):
    """Test suite for live packet capture infrastructure."""

    def test_01_scapy_npcap_driver(self):
        """Verify Scapy library and Npcap driver availability."""
        import scapy
        print(f"\\n[TEST] Scapy Version: {scapy.__version__}")
        self.assertIsNotNone(scapy.__version__)

    def test_02_interface_discovery(self):
        """Verify Windows interface discovery and presence of Wi-Fi 2."""
        ifaces = get_windows_if_list()
        self.assertGreater(len(ifaces), 0, "No network interfaces discovered!")
        
        iface_names = [i.get('name') for i in ifaces if i.get('name')]
        print(f"[TEST] Discovered {len(ifaces)} interfaces. Sample: {iface_names[:5]}")
        
        has_wifi2 = any(i.get('name') == DEFAULT_INTERFACE for i in ifaces)
        print(f"[TEST] Interface '{DEFAULT_INTERFACE}' present: {has_wifi2}")
        self.assertTrue(has_wifi2, f"Target interface '{DEFAULT_INTERFACE}' not found among Windows interfaces!")

    def test_03_short_live_capture(self):
        """Perform a 5-second passive capture to verify packet arrival without exceptions."""
        print(f"[TEST] Starting 5-second passive capture on '{DEFAULT_INTERFACE}'...")
        temp_jsonl = project_root / "data/processed/live/test_temp_flows.jsonl"
        
        result = capture_packets(
            interface=DEFAULT_INTERFACE,
            duration=5,
            timeout_seconds=2.0,
            output_jsonl=str(temp_jsonl)
        )
        
        print(f"[TEST] 5-second capture result: {result}")
        self.assertEqual(result['interface'], DEFAULT_INTERFACE)
        self.assertGreaterEqual(result['duration_seconds'], 4.0)
        self.assertGreaterEqual(result['packets_captured'], 0)
        
        # Clean up temporary test output
        if temp_jsonl.exists():
            temp_jsonl.unlink()


if __name__ == '__main__':
    unittest.main(verbosity=2)
