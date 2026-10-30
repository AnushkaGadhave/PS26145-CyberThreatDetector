"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.capture_service

Stateful, thread-safe background capture service.
Orchestrates live packet sniffing (Scapy/Npcap), flow aggregation (FlowBuilder),
runtime ML threat detection (AlertPipeline), and persistence into PostgreSQL.
"""

import sys
import time
import logging
import threading
from collections import deque
from pathlib import Path
from typing import Dict, List, Any, Optional

import scapy.all as scapy

from src.capture.live_capture import extract_packet_metadata, resolve_interface_name
from src.capture.flow_builder import FlowBuilder
from src.capture.flow_schema import FlowRecord
from src.alerts.alert_pipeline import AlertPipeline
from src.alerts.alert_schema import ThreatAlert
from src.database.database import SessionLocal
from src.database.repository import FlowRepository, AlertRepository

logger = logging.getLogger("src.capture.capture_service")


class LiveCaptureManager:
    """
    Singleton service managing the background network capture thread,
    flow construction, ML inference dispatch, and persistence.
    """
    _instance: Optional["LiveCaptureManager"] = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return

        self._state_lock = threading.Lock()
        self.status: str = "STOPPED"  # STOPPED, STARTING, RUNNING, STOPPING, ERROR
        self.interface: Optional[str] = None
        self.actual_interface: Optional[str] = None
        self.start_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None
        self.error_message: Optional[str] = None
        self.current_user_id: Optional[str] = None

        # Live counters
        self.total_packets: int = 0
        self.ip_packets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.icmp_packets: int = 0
        self.flows_completed: int = 0
        self.alerts_generated: int = 0

        # Ring-buffer of recent live events for UI streaming
        self.recent_events: deque = deque(maxlen=50)

        # Threading handles
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._builder: Optional[FlowBuilder] = None
        self._alert_pipeline: Optional[AlertPipeline] = None

        self._initialized = True

    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        """Discover actual available network interfaces on the Windows host."""
        interfaces = []
        try:
            from scapy.arch.windows import get_windows_if_list
            win_ifaces = get_windows_if_list()
            for iface in win_ifaces:
                name = iface.get("name", "")
                desc = iface.get("description", "")
                ips = iface.get("ips", [])
                is_active = any("192.168" in ip or "10." in ip or "172." in ip for ip in ips)
                # Primary routable IPv4 address or first assigned IP
                primary_ip = next((ip for ip in ips if not ip.startswith("127.") and ":" not in ip), ips[0] if ips else "")
                interfaces.append({
                    "name": name,
                    "description": desc,
                    "ip": primary_ip,
                    "ips": ips,
                    "is_active": is_active,
                    "is_wireless": "Wi-Fi" in name or "Wireless" in desc,
                    "is_loopback": "Loopback" in name or "127.0.0.1" in ips
                })
        except Exception as e:
            logger.warning(f"Could not query Windows interface list via Scapy: {e}")
            # Fallback to conf.ifaces
            for iface_name in scapy.conf.ifaces:
                interfaces.append({
                    "name": str(iface_name),
                    "description": str(iface_name),
                    "ip": "",
                    "ips": [],
                    "is_active": False,
                    "is_wireless": "Wi-Fi" in str(iface_name),
                    "is_loopback": False
                })

        return interfaces

    def start(self, requested_interface: Optional[str] = None, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Start passive network monitoring on the chosen or default interface."""
        with self._state_lock:
            if self.status in ("RUNNING", "STARTING"):
                if user_id and self.current_user_id and self.current_user_id != user_id:
                    return {
                        "success": False,
                        "code": "OCCUPIED_BY_ANOTHER_USER",
                        "message": "Local packet capture is currently active under another user account. Sessions remain isolated.",
                        "status": "OCCUPIED"
                    }
                return {
                    "success": False,
                    "code": "ALREADY_RUNNING",
                    "message": f"Capture is already {self.status} on interface '{self.actual_interface}'.",
                    "status": self.status
                }

            self.status = "STARTING"
            self.error_message = None
            self.current_user_id = user_id

            try:
                # Resolve target interface
                if requested_interface:
                    target_iface = requested_interface
                else:
                    available = self.get_available_interfaces()
                    target_iface = next(
                        (i["name"] for i in available if i.get("is_active") and i.get("is_wireless")),
                        next((i["name"] for i in available if i.get("is_active") and "virtualbox" not in i.get("description", "").lower() and "virtualbox" not in i.get("name", "").lower()), "Wi-Fi 3")
                    )

                self.actual_interface = resolve_interface_name(target_iface)
                self.interface = target_iface

                # Reset counters
                self.start_time = time.time()
                self.last_packet_time = None
                self.total_packets = 0
                self.ip_packets = 0
                self.tcp_packets = 0
                self.udp_packets = 0
                self.icmp_packets = 0
                self.flows_completed = 0
                self.alerts_generated = 0
                self.recent_events.clear()

                # Initialize FlowBuilder with responsive active and protocol-specific timeouts
                self._builder = FlowBuilder(
                    timeout_seconds=30.0,
                    flush_interval_seconds=1.0,
                    active_timeout_seconds=15.0,
                    udp_timeout_seconds=3.0,
                    tcp_idle_timeout_seconds=10.0,
                    consumer_callback=self._on_flow_built,
                    jsonl_path=None,
                    csv_path=None
                )

                # Initialize AlertPipeline with existing trained models
                self._alert_pipeline = AlertPipeline(
                    mode="ALERT",
                    traffic_context="UNLABELED_LIVE",
                    suppression_seconds=15.0,
                    jsonl_path="data/processed/live/alerts/threat_alerts.jsonl",
                    csv_path=None,
                    alert_callback=self._on_alert_generated
                )

                self._stop_event.clear()
                self._thread = threading.Thread(
                    target=self._capture_worker_loop,
                    name="LiveCaptureWorker",
                    daemon=True
                )
                self._thread.start()

                self.status = "RUNNING"
                logger.info(f"Passive live capture worker started on interface '{self.actual_interface}' for user '{user_id}'.")

                return {
                    "success": True,
                    "message": f"Live passive monitoring started on interface '{self.actual_interface}'.",
                    "interface": self.actual_interface,
                    "status": self.status
                }
            except PermissionError as p_err:
                self.status = "ERROR"
                self.error_message = (
                    f"Permission denied starting capture on '{requested_interface or target_iface}': {p_err}. "
                    "Packet capture on Windows requires Administrator privileges or Npcap driver access."
                )
                logger.error(self.error_message)
                return {
                    "success": False,
                    "code": "PERMISSION_REQUIRED",
                    "message": self.error_message,
                    "error": str(p_err),
                    "status": self.status
                }
            except Exception as e:
                self.status = "ERROR"
                err_str = str(e)
                if "access is denied" in err_str.lower() or "winerror 5" in err_str.lower() or "permission" in err_str.lower():
                    self.error_message = (
                        f"Packet capture driver error: {err_str}. "
                        "Verify Npcap installation and Administrator rights."
                    )
                    code = "PERMISSION_REQUIRED"
                elif "interface" in err_str.lower() or "not found" in err_str.lower():
                    self.error_message = f"Interface unavailable: {err_str}"
                    code = "INTERFACE_UNAVAILABLE"
                else:
                    self.error_message = err_str
                    code = "ERROR"

                logger.error(f"Failed to start live capture: {e}", exc_info=True)
                return {
                    "success": False,
                    "code": code,
                    "message": self.error_message,
                    "error": str(e),
                    "status": self.status
                }

    def stop(self, user_id: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
        """Stop passive network monitoring gracefully and flush all flows."""
        with self._state_lock:
            if self.status not in ("RUNNING", "STARTING"):
                return {
                    "success": True,
                    "message": f"Capture is already {self.status}.",
                    "status": self.status
                }

            # Enforce ownership: normal users can only stop their own active capture
            if not is_admin and self.current_user_id and user_id and self.current_user_id != user_id:
                return {
                    "success": False,
                    "code": "FORBIDDEN",
                    "message": "Permission denied: You cannot stop a packet capture session owned by another user.",
                    "status": self.status
                }

            self.status = "STOPPING"
            logger.info("Stopping live capture worker...")

        # Signal background loop to terminate
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        # Flush any remaining active flows from the builder
        if self._builder:
            try:
                logger.info("Flushing remaining active flows...")
                self._builder.flush_all()
            except Exception as e:
                logger.error(f"Error flushing flow builder: {e}")

        with self._state_lock:
            self.status = "STOPPED"
            self.current_user_id = None
            logger.info(
                f"Capture stopped. Summary: {self.total_packets} packets, "
                f"{self.flows_completed} flows, {self.alerts_generated} alerts."
            )

            return {
                "success": True,
                "message": f"Live monitoring stopped. Processed {self.total_packets} packets into {self.flows_completed} flows.",
                "status": self.status,
                "total_packets": self.total_packets,
                "flows_completed": self.flows_completed,
                "alerts_generated": self.alerts_generated
            }

    def _capture_worker_loop(self):
        """Dedicated background thread loop capturing packets in 1-second chunks."""
        actual_iface = self.actual_interface

        def packet_handler(packet):
            if self._stop_event.is_set():
                return

            self.total_packets += 1
            now = time.time()
            self.last_packet_time = now

            meta = extract_packet_metadata(packet)
            if meta is None:
                return

            self.ip_packets += 1
            proto = meta["protocol"]
            if proto == "TCP":
                self.tcp_packets += 1
            elif proto == "UDP":
                self.udp_packets += 1
            elif proto == "ICMP":
                self.icmp_packets += 1

            # Feed to flow builder
            if self._builder:
                self._builder.process_packet(
                    timestamp=meta["timestamp"],
                    src_ip=meta["src_ip"],
                    dst_ip=meta["dst_ip"],
                    src_port=meta["src_port"],
                    dst_port=meta["dst_port"],
                    protocol=meta["protocol"],
                    byte_len=meta["byte_len"],
                    tcp_flags=meta["tcp_flags"]
                )

        try:
            while not self._stop_event.is_set():
                try:
                    scapy.sniff(
                        iface=actual_iface,
                        prn=packet_handler,
                        timeout=1.0,
                        store=0
                    )
                    # Periodically flush expired or closing flows even during low-traffic periods
                    if self._builder and not self._stop_event.is_set():
                        self._builder.flush_expired(time.time())
                except PermissionError as perm_err:
                    if not self._stop_event.is_set():
                        logger.error(f"Permission denied on '{actual_iface}': {perm_err}")
                        self.error_message = (
                            f"Permission denied on interface '{actual_iface}'. "
                            "Packet capture requires elevated privileges or Npcap Administrator driver access."
                        )
                        self.status = "ERROR"
                        break
                except Exception as sniff_err:
                    if not self._stop_event.is_set():
                        err_str = str(sniff_err)
                        logger.error(f"Sniff error on '{actual_iface}': {err_str}")
                        if "access is denied" in err_str.lower() or "winerror 5" in err_str.lower() or "permission" in err_str.lower():
                            self.error_message = (
                                f"Packet capture permission error: {err_str}. "
                                "Requires Administrator privileges or Npcap driver access."
                            )
                        elif "no such device" in err_str.lower() or "device not found" in err_str.lower():
                            self.error_message = f"Interface unavailable: {err_str}"
                        else:
                            self.error_message = str(sniff_err)
                        self.status = "ERROR"
                        break
        except Exception as e:
            logger.error(f"Fatal capture loop error: {e}", exc_info=True)
            self.error_message = str(e)
            self.status = "ERROR"

    def _on_flow_built(self, flow: FlowRecord):
        """Callback invoked whenever FlowBuilder finalizes a flow record."""
        self.flows_completed += 1

        # 1. Persist flow to PostgreSQL
        flow_data = {
            "flow_id": flow.flow_id,
            "timestamp": flow.start_time,
            "start_time": flow.start_time,
            "last_seen": flow.last_seen,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "duration": flow.duration,
            "total_packets": flow.total_packets,
            "total_bytes": flow.total_bytes,
            "forward_packets": flow.forward_packets,
            "backward_packets": flow.backward_packets,
            "forward_bytes": flow.forward_bytes,
            "backward_bytes": flow.backward_bytes,
            "packets_per_second": flow.packets_per_second,
            "bytes_per_second": flow.bytes_per_second,
            "syn_count": flow.syn_count,
            "ack_count": flow.ack_count,
            "fin_count": flow.fin_count,
            "rst_count": flow.rst_count,
            "psh_count": flow.psh_count,
            "urg_count": flow.urg_count,
            "iat_mean": flow.iat_mean,
            "iat_std": flow.iat_std,
            "iat_min": flow.iat_min,
            "iat_max": flow.iat_max,
            "traffic_context": "UNLABELED_LIVE",
            "user_id": getattr(self, "current_user_id", None)
        }

        try:
            with SessionLocal() as db:
                FlowRepository.create_or_update(db, flow_data)
        except Exception as db_err:
            logger.error(f"Failed to persist flow {flow.flow_id} to database: {db_err}")

        # 2. Evaluate flow through trained detection models & alert engine
        generated_alert = None
        if self._alert_pipeline:
            try:
                generated_alert = self._alert_pipeline.process_flow(flow)
            except Exception as det_err:
                logger.error(f"Detection pipeline error on flow {flow.flow_id}: {det_err}")

        # 3. Add to recent live events ring-buffer
        event_dict = {
            "id": f"evt-{int(flow.start_time * 1000)}-{flow.flow_id[-6:]}",
            "timestamp": int(flow.last_seen * 1000),
            "flow_id": flow.flow_id,
            "src_ip": flow.src_ip,
            "dst_ip": flow.dst_ip,
            "src_port": flow.src_port,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "packets": flow.total_packets,
            "bytes": flow.total_bytes,
            "duration": round(flow.duration, 3),
            "threat_outcome": generated_alert.threat_class if generated_alert else "BENIGN",
            "severity": generated_alert.severity if generated_alert else "BENIGN",
            "alert_id": generated_alert.alert_id if generated_alert else None,
            "user_id": getattr(self, "current_user_id", None)
        }
        self.recent_events.appendleft(event_dict)

    def _on_alert_generated(self, alert: ThreatAlert):
        """Callback invoked when AlertPipeline produces a genuine threat alert."""
        self.alerts_generated += 1
        alert_dict = alert.to_dict()
        alert_dict["user_id"] = getattr(self, "current_user_id", None)

        try:
            with SessionLocal() as db:
                AlertRepository.create_or_update(db, alert_dict)
            logger.warning(
                f"[THREAT ALERT] {alert.severity} {alert.threat_class} detected: "
                f"{alert.src_ip} -> {alert.dst_ip} (Score: {alert.confidence})"
            )
        except Exception as db_err:
            logger.error(f"Failed to persist alert {alert.alert_id} to database: {db_err}")

    def get_status(self, user_id: Optional[str] = None, is_admin: bool = False) -> Dict[str, Any]:
        """Returns the real operational status, diagnostics, and volumetric counters of the capture worker."""
        with self._state_lock:
            # Check pcap driver availability
            sensor_installed = bool(getattr(scapy.conf, "use_pcap", False))

            is_owner = (self.current_user_id == user_id) if (user_id and self.current_user_id) else True
            if is_admin:
                is_owner = True

            # If capture is active under another user's session:
            if self.status in ("RUNNING", "STARTING") and not is_owner:
                return {
                    "status": "STANDBY",
                    "state": "STANDBY",
                    "diagnostic_state": "OCCUPIED_BY_ANOTHER_USER",
                    "sensor_installed": sensor_installed,
                    "interface": None,
                    "configured_interface": None,
                    "is_owner": False,
                    "busy_by_other_user": True,
                    "message": "Local packet sniffer is currently in use by another local session. Each user's traffic is isolated.",
                    "total_packets": 0,
                    "packets_captured": 0,
                    "packets_dropped": 0,
                    "ip_packets": 0,
                    "tcp_packets": 0,
                    "udp_packets": 0,
                    "icmp_packets": 0,
                    "flows_completed": 0,
                    "flows_created": 0,
                    "alerts_generated": 0,
                    "threats_detected": 0,
                    "current_pps": 0.0,
                    "current_kbps": 0.0,
                    "error_message": None
                }

            uptime = round(time.time() - self.start_time, 1) if self.start_time and self.status == "RUNNING" else 0.0
            pps = round(self.total_packets / uptime, 1) if uptime > 0 else 0.0
            kbps = round((self.total_packets * 128) / (uptime * 1024), 1) if uptime > 0 else 0.0
            normalized_state = "ACTIVE" if self.status == "RUNNING" else self.status

            # Derive rich diagnostic state
            if not sensor_installed:
                diagnostic_state = "SENSOR_NOT_INSTALLED"
            elif self.status == "ERROR":
                err_low = (self.error_message or "").lower()
                if "permission" in err_low or "access is denied" in err_low or "admin" in err_low or "elevation" in err_low:
                    diagnostic_state = "PERMISSION_REQUIRED"
                elif "interface" in err_low or "not found" in err_low or "unavailable" in err_low:
                    diagnostic_state = "INTERFACE_UNAVAILABLE"
                else:
                    diagnostic_state = "ERROR"
            elif self.status == "RUNNING":
                if uptime >= 2.0 and self.total_packets == 0:
                    diagnostic_state = "RUNNING_NO_PACKETS"
                else:
                    diagnostic_state = "ACTIVE"
            else:
                diagnostic_state = "STANDBY"

            return {
                "status": self.status,
                "state": normalized_state,
                "diagnostic_state": diagnostic_state,
                "sensor_installed": sensor_installed,
                "is_owner": is_owner,
                "busy_by_other_user": False,
                "interface": self.actual_interface,
                "configured_interface": self.interface,
                "start_time": self.start_time,
                "uptime_seconds": uptime,
                "last_packet_time": self.last_packet_time,
                "total_packets": self.total_packets,
                "packets_captured": self.total_packets,
                "packets_dropped": 0,
                "ip_packets": self.ip_packets,
                "tcp_packets": self.tcp_packets,
                "udp_packets": self.udp_packets,
                "icmp_packets": self.icmp_packets,
                "flows_completed": self.flows_completed,
                "flows_created": self.flows_completed,
                "alerts_generated": self.alerts_generated,
                "threats_detected": self.alerts_generated,
                "current_pps": pps,
                "current_kbps": kbps,
                "error_message": self.error_message
            }

    def get_recent_events(self, limit: int = 30, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Return the most recent live stream events from the ring buffer, optionally scoped to a user."""
        if user_id:
            return [e for e in self.recent_events if e.get("user_id") == user_id][:limit]
        return list(self.recent_events)[:limit]


# Global capture manager singleton
capture_manager = LiveCaptureManager()
