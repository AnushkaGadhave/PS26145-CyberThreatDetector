"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.live_capture

Passive, read-only live packet capture and flow extraction engine using Scapy and Npcap.

CRITICAL OPERATIONAL & SAFETY NOTICE:
------------------------------------
This capture engine is passive and read-only. It observes authorized traffic visible
on the selected network interface and does NOT transmit, modify, block, probe, inject,
or decrypt traffic. Zero application payloads or user contents are stored.
"""

import sys
import time
import signal
import logging
import argparse
from pathlib import Path
from typing import Optional, Callable, Dict, Any

import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6

from src.capture.flow_builder import FlowBuilder
from src.capture.flow_schema import FlowRecord

# Configure standard logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s - %(message)s'
)
logger = logging.getLogger("src.capture.live_capture")

# Global default configuration constants
DEFAULT_INTERFACE = "Wi-Fi 2"
DEFAULT_CAPTURE_DURATION = 30
FLOW_TIMEOUT_SECONDS = 60
FLUSH_INTERVAL_SECONDS = 5
DEFAULT_JSONL_PATH = "data/processed/live/live_flows.jsonl"
DEFAULT_CSV_PATH = "data/processed/live/live_flows.csv"


def resolve_interface_name(requested_name: str = DEFAULT_INTERFACE) -> str:
    """
    Resolves the network interface name for Scapy sniffing on Windows.
    Falls back gracefully to the active Wi-Fi / IP adapter if the specified adapter is unavailable.
    """
    try:
        from scapy.arch.windows import get_windows_if_list
        win_ifaces = get_windows_if_list()
        
        # Exact match in windows interface list
        for i in win_ifaces:
            if i.get('name') == requested_name and i.get('ips'):
                return requested_name

        # Check if requested name exists in Scapy conf.ifaces
        if requested_name in scapy.conf.ifaces:
            return requested_name

        # Search for active Wi-Fi interface with assigned IPv4
        for i in win_ifaces:
            name = i.get('name', '')
            ips = i.get('ips', [])
            if ('Wi-Fi' in name or 'Wireless' in str(i.get('description', ''))) and any('192.168' in ip or '10.' in ip or '172.' in ip for ip in ips):
                logger.info(f"Interface '{requested_name}' not active. Auto-selected active Wi-Fi interface: '{name}' ({ips})")
                return name

        # Fallback to any interface with active local IP
        for i in win_ifaces:
            name = i.get('name', '')
            ips = i.get('ips', [])
            if any('192.168' in ip or '10.' in ip for ip in ips):
                logger.info(f"Auto-selected active interface with IP: '{name}' ({ips})")
                return name
    except Exception as e:
        logger.warning(f"Error resolving interface name: {e}")

    return requested_name


class CaptureStatistics:
    """Tracks volumetric counters during packet capture."""
    __slots__ = ('total_packets', 'ip_packets', 'tcp_packets', 'udp_packets', 'icmp_packets', 'ignored_packets', 'start_time', 'end_time')

    def __init__(self):
        self.total_packets = 0
        self.ip_packets = 0
        self.tcp_packets = 0
        self.udp_packets = 0
        self.icmp_packets = 0
        self.ignored_packets = 0
        self.start_time = time.time()
        self.end_time = self.start_time


def extract_packet_metadata(packet: Any) -> Optional[Dict[str, Any]]:
    """
    Extracts pure header metadata from a raw packet.
    Zero payload bytes, application layers, or decrypted contents are accessed or retained.
    """
    ts = float(packet.time) if hasattr(packet, 'time') and packet.time else time.time()
    byte_len = len(packet)

    # IPv4 Handling
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = str(ip_layer.src)
        dst_ip = str(ip_layer.dst)
        proto_num = ip_layer.proto

        if TCP in packet:
            tcp_layer = packet[TCP]
            flags_int = int(tcp_layer.flags)
            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(tcp_layer.sport),
                'dst_port': int(tcp_layer.dport),
                'protocol': 'TCP',
                'byte_len': byte_len,
                'tcp_flags': {
                    'FIN': bool(flags_int & 0x01),
                    'SYN': bool(flags_int & 0x02),
                    'RST': bool(flags_int & 0x04),
                    'PSH': bool(flags_int & 0x08),
                    'ACK': bool(flags_int & 0x10),
                    'URG': bool(flags_int & 0x20)
                }
            }
        elif UDP in packet:
            udp_layer = packet[UDP]
            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(udp_layer.sport),
                'dst_port': int(udp_layer.dport),
                'protocol': 'UDP',
                'byte_len': byte_len,
                'tcp_flags': None
            }
        elif ICMP in packet:
            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': None,
                'dst_port': None,
                'protocol': 'ICMP',
                'byte_len': byte_len,
                'tcp_flags': None
            }
        else:
            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': None,
                'dst_port': None,
                'protocol': f"IP_{proto_num}",
                'byte_len': byte_len,
                'tcp_flags': None
            }

    # IPv6 Handling (Safely supported)
    elif IPv6 in packet:
        ip6_layer = packet[IPv6]
        src_ip = str(ip6_layer.src)
        dst_ip = str(ip6_layer.dst)

        if TCP in packet:
            tcp_layer = packet[TCP]
            flags_int = int(tcp_layer.flags)
            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(tcp_layer.sport),
                'dst_port': int(tcp_layer.dport),
                'protocol': 'TCP',
                'byte_len': byte_len,
                'tcp_flags': {
                    'FIN': bool(flags_int & 0x01),
                    'SYN': bool(flags_int & 0x02),
                    'RST': bool(flags_int & 0x04),
                    'PSH': bool(flags_int & 0x08),
                    'ACK': bool(flags_int & 0x10),
                    'URG': bool(flags_int & 0x20)
                }
            }
        elif UDP in packet:
            udp_layer = packet[UDP]
            return {
                'timestamp': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(udp_layer.sport),
                'dst_port': int(udp_layer.dport),
                'protocol': 'UDP',
                'byte_len': byte_len,
                'tcp_flags': None
            }

    # Non-IP packets (ARP, LLC, spanning tree, etc.)
    return None


def capture_packets(
    interface: str = DEFAULT_INTERFACE,
    duration: int = DEFAULT_CAPTURE_DURATION,
    timeout_seconds: float = FLOW_TIMEOUT_SECONDS,
    flush_interval_seconds: float = FLUSH_INTERVAL_SECONDS,
    output_jsonl: Optional[str] = DEFAULT_JSONL_PATH,
    output_csv: Optional[str] = None,
    packet_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    flow_callback: Optional[Callable[[FlowRecord], None]] = None,
    packet_limit: Optional[int] = None
) -> Dict[str, Any]:
    """
    Executes a passive, read-only live packet capture session.
    Extracts packet metadata, constructs bidirectional flow state, and writes completed flows to disk.
    """
    stats = CaptureStatistics()
    jsonl_p = Path(output_jsonl) if output_jsonl else None
    csv_p = Path(output_csv) if output_csv else None

    # Resolve active interface name
    actual_interface = resolve_interface_name(interface)

    # Initialize Flow Builder
    builder = FlowBuilder(
        timeout_seconds=timeout_seconds,
        flush_interval_seconds=flush_interval_seconds,
        consumer_callback=flow_callback,
        jsonl_path=jsonl_p,
        csv_path=csv_p
    )

    logger.info("=" * 70)
    logger.info("PASSIVE NETWORK CAPTURE INITIALIZED (READ-ONLY)")
    logger.info(f"Target Interface: {interface} -> Using: {actual_interface}")
    logger.info(f"Capture Duration: {duration} seconds")
    logger.info(f"Flow Timeout:     {timeout_seconds} seconds")
    logger.info(f"Output JSONL:     {jsonl_p}")
    logger.info("=" * 70)

    stop_requested = False

    def handle_signal(sig, frame):
        nonlocal stop_requested
        logger.warning("Interrupt signal received. Finalizing flows and shutting down gracefully...")
        stop_requested = True

    # Register signal handlers where supported
    try:
        signal.signal(signal.SIGINT, handle_signal)
    except Exception:
        pass

    def packet_handler(packet):
        if stop_requested:
            return

        stats.total_packets += 1
        meta = extract_packet_metadata(packet)

        if meta is None:
            stats.ignored_packets += 1
            return

        stats.ip_packets += 1
        proto = meta['protocol']
        if proto == 'TCP':
            stats.tcp_packets += 1
        elif proto == 'UDP':
            stats.udp_packets += 1
        elif proto == 'ICMP':
            stats.icmp_packets += 1

        # Feed metadata to FlowBuilder
        builder.process_packet(
            timestamp=meta['timestamp'],
            src_ip=meta['src_ip'],
            dst_ip=meta['dst_ip'],
            src_port=meta['src_port'],
            dst_port=meta['dst_port'],
            protocol=meta['protocol'],
            byte_len=meta['byte_len'],
            tcp_flags=meta['tcp_flags']
        )

        if packet_callback:
            try:
                packet_callback(meta)
            except Exception as e:
                logger.error(f"Error in packet_callback: {e}")

    try:
        # Sniff packets passively. store=0 ensures zero packet buffering in RAM.
        scapy.sniff(
            iface=actual_interface,
            prn=packet_handler,
            timeout=duration,
            count=packet_limit or 0,
            store=0
        )
    except Exception as e:
        logger.error(f"Capture encountered an exception on interface '{actual_interface}': {e}")
        raise
    finally:
        # Flush all remaining active flows upon capture completion
        stats.end_time = time.time()
        logger.info("Sniffing finished. Flushing remaining active flows...")
        builder.flush_all()

    actual_duration = round(stats.end_time - stats.start_time, 2)

    summary_result = {
        'interface': interface,
        'actual_interface': actual_interface,
        'duration_seconds': actual_duration,
        'packets_captured': stats.total_packets,
        'ip_packets': stats.ip_packets,
        'tcp_packets': stats.tcp_packets,
        'udp_packets': stats.udp_packets,
        'icmp_packets': stats.icmp_packets,
        'ignored_packets': stats.ignored_packets,
        'completed_flows': builder.completed_flow_count,
        'remaining_active_flows': builder.active_flow_count,
        'output_jsonl': str(jsonl_p) if jsonl_p else None,
        'output_csv': str(csv_p) if csv_p else None
    }

    print("\n" + "=" * 50)
    print("LIVE CAPTURE COMPLETE")
    print("=" * 50)
    print(f"Interface:              {summary_result['interface']}")
    print(f"Duration:               {summary_result['duration_seconds']}s")
    print(f"Packets captured:       {summary_result['packets_captured']}")
    print(f"IP packets:             {summary_result['ip_packets']}")
    print(f"TCP packets:            {summary_result['tcp_packets']}")
    print(f"UDP packets:            {summary_result['udp_packets']}")
    print(f"ICMP packets:           {summary_result['icmp_packets']}")
    print(f"Ignored packets:        {summary_result['ignored_packets']}")
    print(f"Completed flows:        {summary_result['completed_flows']}")
    print(f"Remaining active flows: {summary_result['remaining_active_flows']}")
    print(f"Output file:            {summary_result['output_jsonl']}")
    print("=" * 50)

    return summary_result


def main():
    parser = argparse.ArgumentParser(
        description="Passive Real-Time Network Packet Capture & Flow Extraction (SIH 26145)"
    )
    parser.add_argument("--interface", type=str, default=DEFAULT_INTERFACE, help="Network adapter name (default: 'Wi-Fi 2')")
    parser.add_argument("--duration", type=int, default=DEFAULT_CAPTURE_DURATION, help="Capture duration in seconds (default: 30)")
    parser.add_argument("--timeout", type=float, default=FLOW_TIMEOUT_SECONDS, help="Flow inactivity timeout in seconds (default: 60)")
    parser.add_argument("--output", type=str, default=DEFAULT_JSONL_PATH, help="Output JSONL path for completed flows")
    parser.add_argument("--csv", type=str, default=None, help="Optional output CSV path")
    parser.add_argument("--limit", type=int, default=None, help="Optional maximum packet count limit")

    args = parser.parse_args()

    capture_packets(
        interface=args.interface,
        duration=args.duration,
        timeout_seconds=args.timeout,
        output_jsonl=args.output,
        output_csv=args.csv,
        packet_limit=args.limit
    )


if __name__ == "__main__":
    main()
