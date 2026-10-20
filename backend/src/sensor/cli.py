"""
NETRA Local Windows Sensor - Command Line Interface
Provides terminal controls for:
- Discovering host network interfaces
- Launching the passive sensor on a chosen adapter
- Displaying real-time volumetric traffic counters and flow rates
- Inspecting the local metadata queue and disk spool
"""

import sys
import time
import json
import signal
import logging
import argparse
from pathlib import Path

# Add backend directory to path if executed standalone
backend_dir = Path(__file__).resolve().parent.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from src.sensor.config import SensorConfig
from src.sensor.interface_manager import InterfaceManager
from src.sensor.windows_sensor import WindowsSensor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s"
)
logger = logging.getLogger("netra.sensor.cli")


def print_banner():
    banner = r"""
========================================================================
   NETRA - Local Windows Network Threat Sensor (Passive Sniffer)
   AI-Based Threat Detection in Unidirectional IP Traffic (SIH PS 26145)
========================================================================
[CRITICAL SAFETY POLICY]
- Mode: Passive, Read-Only Network Ingress Sniffing (Npcap / Scapy)
- Zero packet transmission, probe generation, or active scanning.
- Zero payload retention; header metadata and volumetric timing only.
- Local metadata queue staging enabled for future cloud delivery.
========================================================================
"""
    print(banner)


def cmd_list_interfaces():
    """Prints a formatted table of all network adapters available on this host."""
    print("\n--- DISCOVERED NETWORK INTERFACES ---")
    interfaces = InterfaceManager.list_interfaces(active_only=False)

    if not interfaces:
        print("No network interfaces discovered!")
        return

    print(f"{'#':<3} {'INTERFACE NAME':<28} {'STATUS':<10} {'TYPE':<10} {'IPV4 ADDRESS':<18} {'MAC ADDRESS'}")
    print("-" * 90)
    for idx, iface in enumerate(interfaces, 1):
        status = "ACTIVE" if iface.is_active else "STANDBY"
        itype = "Wi-Fi" if iface.is_wireless else ("Loopback" if iface.is_loopback else "Ethernet")
        v4 = iface.ipv4_addresses[0] if iface.ipv4_addresses else "(none)"
        mac = iface.mac_address or "(none)"
        print(f"{idx:<3} {iface.name:<28} {status:<10} {itype:<10} {v4:<18} {mac}")
    print("-" * 90)
    print(f"Total discovered adapters: {len(interfaces)}")


def cmd_inspect_queue(sensor: WindowsSensor):
    """Prints summary and sample records from the local metadata queue."""
    stats = sensor.metadata_queue.stats()
    print("\n--- LOCAL METADATA QUEUE STATUS ---")
    print(f"Pending in-memory records: {stats['pending_queue_size']}")
    print(f"Cumulative enqueued:        {stats['enqueued_total']}")
    print(f"Cumulative dequeued:        {stats['dequeued_total']}")
    print(f"Cumulative dropped:         {stats['dropped_total']}")
    print(f"Persistent disk spool:      {stats['spool_file_path']}")
    print(f"Spool file size:            {stats['spool_file_size_bytes']} bytes")
    print("-" * 60)

    sample = sensor.metadata_queue.peek(limit=5)
    total_on_disk = 0
    if sensor.metadata_queue.spool_path.exists():
        try:
            with open(sensor.metadata_queue.spool_path, "r", encoding="utf-8") as f:
                lines = [line for line in f if line.strip()]
                total_on_disk = len(lines)
                if not sample and lines:
                    sample = [json.loads(line) for line in lines[-5:]]
        except Exception as e:
            logger.error(f"Error reading spool file: {e}")

    print(f"Total persistent records on disk: {total_on_disk}")
    print("-" * 60)

    if sample:
        print(f"Showing {len(sample)} most recent record(s):")
        for idx, rec in enumerate(sample, 1):
            flow = rec.get("flow", {})
            src_port = flow.get('src_port')
            dst_port = flow.get('dst_port')
            src = f"{flow.get('src_ip')}:{src_port}" if src_port is not None else str(flow.get('src_ip'))
            dst = f"{flow.get('dst_ip')}:{dst_port}" if dst_port is not None else str(flow.get('dst_ip'))
            proto = flow.get("protocol", "IP")
            pkts = flow.get("total_packets", 0)
            bytes_len = flow.get("total_bytes", 0)
            status = rec.get("delivery_status", "PENDING_LOCAL")
            det = rec.get("detection") or {}
            threat = det.get("threat_class", "BENIGN")
            sev = det.get("severity", "BENIGN")
            print(f"  [{idx}] {rec.get('record_id')} ({rec.get('record_type')} | {status})")
            print(f"      {proto} {src} -> {dst} | {pkts} pkts, {bytes_len} bytes | Verdict: {threat} ({sev})")
    else:
        print("No pending records in memory queue or spool file.")


def main():
    parser = argparse.ArgumentParser(
        description="NETRA Local Windows Passive Sensor - Live Network Threat Telemetry (SIH PS 26145)"
    )
    parser.add_argument(
        "--list-interfaces", "-l",
        action="store_true",
        help="List available network interfaces on this machine and exit"
    )
    parser.add_argument(
        "--interface", "-i",
        type=str,
        default=None,
        help="Target network interface name to monitor (e.g., 'Wi-Fi 2', 'Wi-Fi 3'). If omitted, auto-selects active adapter."
    )
    parser.add_argument(
        "--duration", "-d",
        type=float,
        default=None,
        help="Capture duration in seconds. If omitted, runs continuously until Ctrl+C."
    )
    parser.add_argument(
        "--flow-timeout", "-t",
        type=float,
        default=30.0,
        help="Flow inactivity timeout in seconds (default: 30.0s)"
    )
    parser.add_argument(
        "--spool-dir",
        type=str,
        default="data/sensor_queue",
        help="Local directory for queue persistence (default: 'data/sensor_queue')"
    )
    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Disable local ML threat detection evaluation (pure telemetry capture)"
    )
    parser.add_argument(
        "--no-validation",
        action="store_true",
        help="Disable schema feature validation"
    )
    parser.add_argument(
        "--inspect-queue",
        action="store_true",
        help="Inspect local metadata queue status and recent queued records, then exit"
    )

    args = parser.parse_args()

    if args.list_interfaces:
        print_banner()
        cmd_list_interfaces()
        return

    config = SensorConfig(
        interface=args.interface,
        duration=args.duration,
        flow_timeout=args.flow_timeout,
        queue_spool_dir=args.spool_dir,
        enable_detection=not args.no_ml,
        enable_feature_validation=not args.no_validation
    )

    sensor = WindowsSensor(config=config)

    if args.inspect_queue:
        print_banner()
        cmd_inspect_queue(sensor)
        return

    print_banner()

    # Graceful SIGINT / SIGTERM handling
    stop_event = False

    def handle_signal(sig, frame):
        nonlocal stop_event
        if not stop_event:
            stop_event = True
            print("\n[!] Shutdown signal received. Finalizing in-flight flows and queueing metadata...")
            sensor.stop()

    signal.signal(signal.SIGINT, handle_signal)

    # Start sensor
    print(f"[*] Starting sensor on interface: {args.interface or 'Auto-Select'}...")
    res = sensor.start(args.interface)
    if not res.get("success"):
        print(f"\n[ERROR] Failed to start sensor: {res.get('message')}")
        sys.exit(1)

    print(f"[+] Passive capture active on: {sensor.actual_interface}")
    print(f"[*] Telemetry staging into local queue: {config.queue_spool_dir}")
    print("[*] Press Ctrl+C to halt capture gracefully.\n")

    start_t = time.time()
    try:
        while not stop_event and sensor.status == "RUNNING":
            elapsed = time.time() - start_t
            if args.duration and elapsed >= args.duration:
                print(f"\n[*] Configured capture duration ({args.duration}s) reached.")
                break

            time.sleep(2.0)
            status = sensor.get_status()
            sys.stdout.write(
                f"\r[Uptime: {status['uptime_seconds']:>5.1f}s] "
                f"Packets: {status['packets_captured']:>5} "
                f"({status['current_pps']:>5.1f} pps) | "
                f"Flows: {status['flows_completed']:>4} | "
                f"Threats: {status['threats_detected']:>3} | "
                f"Queued: {status['queue_pending']:>4}  "
            )
            sys.stdout.flush()

    except KeyboardInterrupt:
        pass
    finally:
        if sensor.status in ("RUNNING", "STARTING"):
            sensor.stop()

    print("\n" + "=" * 60)
    print("NETRA SENSOR RUN COMPLETE")
    print("=" * 60)
    final_status = sensor.get_status()
    print(f"Interface:            {final_status['interface']}")
    print(f"Total Duration:       {final_status['uptime_seconds']}s")
    print(f"Packets Captured:     {final_status['packets_captured']}")
    print(f"IP Packets:           {final_status['ip_packets']}")
    print(f"TCP / UDP / ICMP:     {final_status['tcp_packets']} / {final_status['udp_packets']} / {final_status['icmp_packets']}")
    print(f"Completed Flows:      {final_status['flows_completed']}")
    print(f"Active Flows:         {final_status['active_flows']}")
    print(f"Threats Detected:     {final_status['threats_detected']}")
    print(f"Metadata Queued:      {final_status['queue_enqueued']}")
    print(f"Disk Spool Path:      {sensor.metadata_queue.spool_path}")
    print("=" * 60)


if __name__ == "__main__":
    main()
