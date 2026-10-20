"""
NETRA Local Windows Sensor - Core Sensor Implementation
Integrates:
- Interface discovery and explicit selection (InterfaceManager)
- Passive Npcap/Scapy live packet sniffing (zero injection, store=0)
- Bidirectional flow aggregation (FlowBuilder, FlowRecord)
- Feature validation against trained model schemas (FeatureValidator)
- Multicast & local discovery safety guards (Safety)
- Multi-threat detection and calibrated alert engine (AlertPipeline / ThreatDetector)
- Local metadata queue interface for future cloud transmission (LocalMetadataQueue)
- Clean lifecycle controls (start, stop, restart, get_status)
"""

import sys
import time
import socket
import logging
import threading
from pathlib import Path
from collections import deque
from typing import Dict, List, Any, Optional, Callable, Union

import scapy.all as scapy

from src.capture.live_capture import extract_packet_metadata
from src.capture.flow_builder import FlowBuilder
from src.capture.flow_schema import FlowRecord
from src.detection.feature_adapter import FeatureAdapter
from src.alerts.alert_pipeline import AlertPipeline
from src.alerts.alert_schema import ThreatAlert

from src.sensor.config import SensorConfig
from src.sensor.interface_manager import InterfaceManager, InterfaceNotFoundError, NetworkInterfaceDetails
from src.sensor.metadata_queue import LocalMetadataQueue, MetadataRecord
from src.sensor.feature_validator import FeatureValidator
from src.sensor.safety import (
    evaluate_multicast_discovery_safety,
    prevent_c2_multicast_misclassification,
    is_established_web_flow
)

logger = logging.getLogger("src.sensor.windows_sensor")


class CaptureError(Exception):
    """Base exception for network capture failures."""
    pass


class CapturePermissionError(CaptureError):
    """Raised when process lacks Administrator or Npcap packet capture privileges."""
    pass


class InterfaceUnavailableError(CaptureError):
    """Raised when an interface cannot be opened for sniffing."""
    pass


class WindowsSensor:
    """
    Modular, passive Windows network sensor for NETRA.
    """
    def __init__(self, config: Optional[SensorConfig] = None):
        self.config = config or SensorConfig()
        self._lock = threading.Lock()

        # Operational state: STOPPED, STARTING, RUNNING, STOPPING, ERROR
        self.status: str = "STOPPED"
        self.configured_interface: Optional[str] = self.config.interface
        self.actual_interface: Optional[str] = None
        self.interface_details: Optional[NetworkInterfaceDetails] = None
        self.error_message: Optional[str] = None

        # Temporal bounds
        self.start_time: Optional[float] = None
        self.stop_time: Optional[float] = None
        self.last_packet_time: Optional[float] = None

        # Volumetric counters (packet level)
        self.packets_captured: int = 0
        self.packets_dropped: int = 0
        self.ip_packets: int = 0
        self.tcp_packets: int = 0
        self.udp_packets: int = 0
        self.icmp_packets: int = 0
        self.other_packets: int = 0
        self.bytes_captured: int = 0

        # Flow counters
        self.flows_created: int = 0
        self.flows_completed: int = 0

        # Detection counters
        self.threats_detected: int = 0
        self.threat_counts: Dict[str, int] = {
            "DDoS": 0,
            "RECON_PORTSCAN": 0,
            "BOTNET_C2": 0,
            "MULTI_THREAT": 0,
            "BENIGN": 0
        }
        self.last_threat_timestamp: Optional[float] = None

        # Subsystems
        self.metadata_queue = LocalMetadataQueue(
            max_size=self.config.queue_max_size,
            spool_dir=self.config.queue_spool_dir,
            spool_filename=self.config.spool_filename,
            enable_disk_spool=self.config.enable_spooling
        )
        self.feature_validator = FeatureValidator(
            ddos_config_path=self.config.ddos_config_path,
            portscan_config_path=self.config.portscan_config_path,
            c2_config_path=f"{self.config.c2_models_dir}/c2_model_config.json"
        )
        self.adapter = FeatureAdapter(
            ddos_config_path=self.config.ddos_config_path,
            c2_config_path=f"{self.config.c2_models_dir}/c2_model_config.json",
            portscan_config_path=self.config.portscan_config_path
        )

        self._builder: Optional[FlowBuilder] = None
        self._alert_pipeline: Optional[AlertPipeline] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Ring buffer of recent flow events for live monitoring
        self.recent_events: deque = deque(maxlen=50)

        # Callbacks
        self.flow_callbacks: List[Callable[[FlowRecord], None]] = []
        self.alert_callbacks: List[Callable[[ThreatAlert], None]] = []

    def register_flow_callback(self, callback: Callable[[FlowRecord], None]):
        """Register a consumer callback for completed flows."""
        self.flow_callbacks.append(callback)

    def register_alert_callback(self, callback: Callable[[ThreatAlert], None]):
        """Register a consumer callback for threat alerts."""
        self.alert_callbacks.append(callback)

    def get_available_interfaces(self) -> List[Dict[str, Any]]:
        """List all discovered network interfaces on this Windows machine."""
        return [i.to_dict() for i in InterfaceManager.list_interfaces(active_only=False)]

    def start(self, requested_interface: Optional[str] = None) -> Dict[str, Any]:
        """
        Starts passive packet capture on the specified or configured network interface.
        """
        with self._lock:
            if self.status in ("RUNNING", "STARTING"):
                return {
                    "success": False,
                    "message": f"Sensor is already {self.status} on interface '{self.actual_interface}'.",
                    "status": self.status,
                    "interface": self.actual_interface
                }

            self.status = "STARTING"
            self.error_message = None

            # 1. Resolve and validate interface
            target_iface_name = requested_interface or self.config.interface
            try:
                # If explicitly requested, enforce existence
                if target_iface_name:
                    resolved_name = InterfaceManager.resolve_interface(target_iface_name, auto_fallback=False)
                else:
                    resolved_name = InterfaceManager.resolve_interface(None, auto_fallback=True)

                self.actual_interface = resolved_name
                self.configured_interface = target_iface_name
                self.interface_details = InterfaceManager.get_interface(resolved_name)
            except InterfaceNotFoundError as inf_err:
                self.status = "ERROR"
                self.error_message = str(inf_err)
                logger.error(f"[SENSOR START ERROR] {inf_err}")
                return {
                    "success": False,
                    "message": str(inf_err),
                    "error": "INTERFACE_NOT_FOUND",
                    "status": self.status
                }
            except Exception as res_err:
                self.status = "ERROR"
                self.error_message = f"Interface resolution error: {res_err}"
                logger.error(f"[SENSOR START ERROR] {res_err}", exc_info=True)
                return {
                    "success": False,
                    "message": self.error_message,
                    "error": "RESOLUTION_FAILED",
                    "status": self.status
                }

            # 2. Reset volumetric and temporal counters
            self.start_time = time.time()
            self.stop_time = None
            self.last_packet_time = None
            self.packets_captured = 0
            self.packets_dropped = 0
            self.ip_packets = 0
            self.tcp_packets = 0
            self.udp_packets = 0
            self.icmp_packets = 0
            self.other_packets = 0
            self.bytes_captured = 0
            self.flows_created = 0
            self.flows_completed = 0
            self.threats_detected = 0
            self.recent_events.clear()

            # 3. Initialize FlowBuilder
            self._builder = FlowBuilder(
                timeout_seconds=self.config.flow_timeout,
                flush_interval_seconds=self.config.flow_flush_interval,
                consumer_callback=self._handle_completed_flow,
                jsonl_path=None,
                csv_path=None
            )

            # 4. Initialize ML AlertPipeline if enabled
            if self.config.enable_detection:
                try:
                    self._alert_pipeline = AlertPipeline(
                        mode="ALERT",
                        traffic_context=self.config.traffic_context,
                        suppression_seconds=self.config.suppression_window_seconds,
                        jsonl_path=None,
                        csv_path=None,
                        alert_callback=None
                    )
                except Exception as det_init_err:
                    logger.warning(f"Detection pipeline init warning (proceeding without local ML): {det_init_err}")
                    self._alert_pipeline = None

            # 5. Launch background sniffing worker
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._worker_capture_loop,
                name=f"NETRA-SensorWorker-{self.actual_interface}",
                daemon=True
            )

            try:
                self._thread.start()
                self.status = "RUNNING"
                logger.info(
                    f"NETRA Local Windows Sensor active on interface '{self.actual_interface}'. "
                    f"Passive read-only capture initiated."
                )
                return {
                    "success": True,
                    "message": f"Sensor successfully started on interface '{self.actual_interface}'.",
                    "status": self.status,
                    "interface": self.actual_interface,
                    "details": self.interface_details.to_dict() if self.interface_details else None
                }
            except Exception as start_err:
                self.status = "ERROR"
                self.error_message = f"Failed to start sniffer worker thread: {start_err}"
                logger.error(self.error_message, exc_info=True)
                return {
                    "success": False,
                    "message": self.error_message,
                    "error": "WORKER_START_FAILED",
                    "status": self.status
                }

    def stop(self) -> Dict[str, Any]:
        """
        Gracefully stops live packet capture and finalizes all active flows.
        """
        with self._lock:
            if self.status not in ("RUNNING", "STARTING"):
                return {
                    "success": True,
                    "message": f"Sensor is already {self.status}.",
                    "status": self.status,
                    "packets_captured": self.packets_captured,
                    "flows_completed": self.flows_completed
                }

            self.status = "STOPPING"
            self.stop_time = time.time()
            logger.info("Stopping NETRA Windows Sensor worker...")

        # Signal sniffer loop to exit
        self._stop_event.set()

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.5)

        # Flush any remaining active flows from the flow builder
        if self._builder:
            try:
                logger.info("Flushing all remaining active flows from FlowBuilder...")
                self._builder.flush_all()
            except Exception as flush_err:
                logger.error(f"Error flushing flow builder: {flush_err}")

        with self._lock:
            self.status = "STOPPED"
            duration = round((self.stop_time or time.time()) - (self.start_time or time.time()), 2)
            logger.info(
                f"NETRA Sensor stopped cleanly. Uptime: {duration}s | "
                f"Packets: {self.packets_captured} | Flows: {self.flows_completed} | "
                f"Threats: {self.threats_detected} | Queued: {self.metadata_queue.enqueued_count}"
            )

            return {
                "success": True,
                "message": f"Sensor stopped cleanly. Processed {self.packets_captured} packets into {self.flows_completed} flows.",
                "status": self.status,
                "duration_seconds": duration,
                "packets_captured": self.packets_captured,
                "packets_dropped": self.packets_dropped,
                "flows_completed": self.flows_completed,
                "threats_detected": self.threats_detected,
                "queued_records": self.metadata_queue.qsize()
            }

    def restart(self, requested_interface: Optional[str] = None) -> Dict[str, Any]:
        """Gracefully stops and restarts the sensor."""
        self.stop()
        time.sleep(0.5)
        return self.start(requested_interface)

    def _worker_capture_loop(self):
        """
        Background worker thread executing passive Scapy packet capture.
        Sniffs in 1-second bounded chunks to check stop event cleanly.
        """
        iface = self.actual_interface

        def on_packet(packet):
            if self._stop_event.is_set():
                return

            self.packets_captured += 1
            now = time.time()
            self.last_packet_time = now

            meta = extract_packet_metadata(packet)
            if meta is None:
                self.other_packets += 1
                return

            self.ip_packets += 1
            byte_len = meta.get("byte_len", 0)
            self.bytes_captured += byte_len

            proto = meta.get("protocol", "")
            if proto == "TCP":
                self.tcp_packets += 1
            elif proto == "UDP":
                self.udp_packets += 1
            elif proto == "ICMP":
                self.icmp_packets += 1
            else:
                self.other_packets += 1

            # Dispatch to FlowBuilder
            if self._builder:
                self._builder.process_packet(
                    timestamp=meta["timestamp"],
                    src_ip=meta["src_ip"],
                    dst_ip=meta["dst_ip"],
                    src_port=meta["src_port"],
                    dst_port=meta["dst_port"],
                    protocol=meta["protocol"],
                    byte_len=meta["byte_len"],
                    tcp_flags=meta.get("tcp_flags")
                )

        # Scapy sniffing loop
        try:
            while not self._stop_event.is_set():
                try:
                    scapy.sniff(
                        iface=iface,
                        prn=on_packet,
                        timeout=1.0,
                        store=0  # ZERO payload or packet buffering in RAM
                    )
                except PermissionError as perm_err:
                    logger.error(f"Permission denied while capturing on '{iface}': {perm_err}")
                    self.error_message = (
                        f"Permission denied opening adapter '{iface}'. "
                        "Ensure the process runs with Administrator privileges and Npcap driver is installed."
                    )
                    self.status = "ERROR"
                    break
                except ValueError as val_err:
                    logger.error(f"Interface error on '{iface}': {val_err}")
                    self.error_message = f"Interface error on '{iface}': {val_err}"
                    self.status = "ERROR"
                    break
                except Exception as sniff_err:
                    if not self._stop_event.is_set():
                        err_str = str(sniff_err)
                        logger.error(f"Sniffer exception on '{iface}': {err_str}")
                        if "pcap" in err_str.lower() or "winerror" in err_str.lower() or "access is denied" in err_str.lower():
                            self.error_message = (
                                f"Packet capture driver error: {err_str}. "
                                "Verify Npcap installation and Administrator rights."
                            )
                        else:
                            self.error_message = f"Capture failure on '{iface}': {err_str}"
                        self.status = "ERROR"
                        break
        except Exception as fatal_err:
            logger.error(f"Fatal sensor worker loop exception: {fatal_err}", exc_info=True)
            self.error_message = str(fatal_err)
            self.status = "ERROR"

    def _handle_completed_flow(self, flow: FlowRecord):
        """
        Handler invoked whenever FlowBuilder finalizes a flow record.
        Coordinates feature validation, ML inference, safety policy, and queueing.
        """
        self.flows_completed += 1

        # 1. Feature validation against model schemas
        validation_summary = {}
        if self.config.enable_feature_validation:
            try:
                validation_results = self.feature_validator.validate_flow_all_models(self.adapter, flow)
                validation_summary = {
                    k: {
                        "is_valid": v.is_valid,
                        "expected_count": v.expected_count,
                        "actual_count": v.actual_count,
                        "ordering_matches": v.ordering_matches,
                        "error": v.error_message
                    }
                    for k, v in validation_results.items()
                }
            except Exception as val_err:
                logger.error(f"Error during feature validation for flow {flow.flow_id}: {val_err}")
                validation_summary = {"error": str(val_err)}

        # 2. Check multicast / discovery traffic safety guard
        is_discovery, discovery_reason = evaluate_multicast_discovery_safety(
            flow.src_ip, flow.dst_ip, flow.dst_port, flow.protocol
        )

        # 3. ML Threat Evaluation
        generated_alert: Optional[ThreatAlert] = None
        detection_summary: Optional[Dict[str, Any]] = None

        if self._alert_pipeline and self.config.enable_detection:
            try:
                # If traffic is local discovery, prevent false C2 classification
                generated_alert = self._alert_pipeline.process_flow(flow)

                if generated_alert:
                    # Apply safety guard: suppress C2 on discovery traffic or unconfirmed QUIC web egress
                    if generated_alert.threat_class == "BOTNET_C2":
                        if is_discovery:
                            logger.info(
                                f"[SAFETY] Suppressing C2 alert on discovery flow {flow.flow_id} "
                                f"({flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}) - {discovery_reason}"
                            )
                            generated_alert = None
                        elif (flow.protocol or "").upper() == "UDP" and flow.dst_port == 443:
                            # Standard QUIC web traffic: suppress unless proven beaconing regularity exists
                            c2_feats = self.adapter.to_c2_dataframe(flow).iloc[0].to_dict()
                            iat_reg = c2_feats.get('IAT_Regularity_Causal', 0.0)
                            obs = c2_feats.get('SrcDst_Flows_BeforeOrAtT', 0)
                            if obs < 3 or iat_reg < 0.5:
                                logger.info(
                                    f"[SAFETY] Suppressed false C2 alert on standard QUIC web egress: "
                                    f"{flow.src_ip} -> {flow.dst_ip}:{flow.dst_port} (obs={obs}, reg={iat_reg:.2f})"
                                )
                                generated_alert = None
                    elif generated_alert.threat_class == "RECON_PORTSCAN":
                        # Prevent misclassification of established HTTPS sessions or local broadcast/discovery as PortScan
                        if is_established_web_flow(flow.protocol, flow.dst_port, flow.total_packets, flow.total_bytes, flow.ack_count):
                            logger.info(
                                f"[SAFETY] Suppressed false PortScan alert on established web flow {flow.flow_id} "
                                f"({flow.src_ip} -> {flow.dst_ip}:{flow.dst_port}, {flow.total_packets} pkts, {flow.total_bytes} bytes)"
                            )
                            generated_alert = None
                        elif is_discovery:
                            logger.info(
                                f"[SAFETY] Suppressed false PortScan alert on local discovery/broadcast flow {flow.flow_id} - {discovery_reason}"
                            )
                            generated_alert = None

                if generated_alert:
                    self._handle_generated_alert(generated_alert)
                    detection_summary = {
                        "evaluated": True,
                        "alert_id": generated_alert.alert_id,
                        "threat_class": generated_alert.threat_class,
                        "severity": generated_alert.severity,
                        "confidence": generated_alert.confidence,
                        "confidence_band": generated_alert.confidence_band,
                        "evidence_summary": generated_alert.evidence_summary
                    }
                else:
                    detection_summary = {
                        "evaluated": True,
                        "threat_class": "BENIGN",
                        "severity": "BENIGN",
                        "confidence": 0.0,
                        "is_discovery": is_discovery,
                        "discovery_reason": discovery_reason
                    }
            except Exception as det_err:
                logger.error(f"ML threat evaluation error on flow {flow.flow_id}: {det_err}")
                detection_summary = {"evaluated": False, "error": str(det_err)}

        # 4. Enqueue into LocalMetadataQueue for future cloud ingestion
        record_id = f"meta_{int(flow.start_time * 1000)}_{flow.flow_id[-8:]}"
        meta_record = MetadataRecord(
            record_id=record_id,
            sensor_id=self.config.sensor_id,
            sensor_version=self.config.sensor_version,
            hostname=socket.gethostname() or "win-host",
            timestamp=flow.start_time,
            record_type="FLOW",
            interface=self.actual_interface or "unknown",
            flow=flow.to_dict(),
            validation=validation_summary,
            detection=detection_summary,
            delivery_status="PENDING_LOCAL"
        )
        self.metadata_queue.enqueue(meta_record)

        # 5. Push to live UI stream event buffer
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
            "alert_id": generated_alert.alert_id if generated_alert else None
        }
        self.recent_events.appendleft(event_dict)

        # 6. Notify registered flow callbacks
        for cb in self.flow_callbacks:
            try:
                cb(flow)
            except Exception as cb_err:
                logger.error(f"Error in flow consumer callback: {cb_err}")

    def _handle_generated_alert(self, alert: ThreatAlert):
        """Handler for genuine threat alerts emitted by the AlertPipeline."""
        self.threats_detected += 1
        t_cls = alert.threat_class
        self.threat_counts[t_cls] = self.threat_counts.get(t_cls, 0) + 1
        self.last_threat_timestamp = alert.timestamp

        # Enqueue alert into metadata queue
        alert_meta = MetadataRecord(
            record_id=f"alert_meta_{int(alert.timestamp * 1000)}_{alert.alert_id[-8:]}",
            sensor_id=self.config.sensor_id,
            sensor_version=self.config.sensor_version,
            hostname=socket.gethostname() or "win-host",
            timestamp=alert.timestamp,
            record_type="THREAT_ALERT",
            interface=self.actual_interface or "unknown",
            flow={
                "flow_id": alert.flow_id,
                "src_ip": alert.src_ip,
                "dst_ip": alert.dst_ip,
                "src_port": alert.src_port,
                "dst_port": alert.dst_port,
                "protocol": alert.protocol,
                "total_packets": alert.total_packets,
                "total_bytes": alert.total_bytes,
                "duration": alert.flow_duration
            },
            detection=alert.to_dict(),
            delivery_status="PENDING_LOCAL"
        )
        self.metadata_queue.enqueue(alert_meta)

        # Notify registered alert callbacks
        for cb in self.alert_callbacks:
            try:
                cb(alert)
            except Exception as cb_err:
                logger.error(f"Error in alert consumer callback: {cb_err}")

    def get_status(self) -> Dict[str, Any]:
        """
        Returns comprehensive operational health, accurate counters, and queue metrics.
        Strictly distinguishes capture status from threat detection verdicts.
        """
        now = time.time()
        if self.status == "RUNNING" and self.start_time:
            uptime = round(now - self.start_time, 2)
        elif self.start_time and self.stop_time:
            uptime = round(self.stop_time - self.start_time, 2)
        else:
            uptime = 0.0

        pps = round(self.packets_captured / uptime, 1) if uptime > 0 else 0.0
        kbps = round((self.bytes_captured / 1024.0) / uptime, 1) if uptime > 0 else 0.0
        normalized_state = "ACTIVE" if self.status == "RUNNING" else self.status

        active_flow_cnt = self._builder.active_flow_count if self._builder else 0
        queue_stats = self.metadata_queue.stats()

        return {
            # Operational Capture Health
            "status": self.status,
            "state": normalized_state,
            "sensor_id": self.config.sensor_id,
            "sensor_version": self.config.sensor_version,
            "interface": self.actual_interface,
            "configured_interface": self.configured_interface,
            "start_time": self.start_time,
            "uptime_seconds": uptime,
            "last_packet_time": self.last_packet_time,
            "error_message": self.error_message,

            # Volumetric Traffic Counters
            "packets_captured": self.packets_captured,
            "total_packets": self.packets_captured,
            "packets_dropped": self.packets_dropped,
            "bytes_captured": self.bytes_captured,
            "ip_packets": self.ip_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "other_packets": self.other_packets,
            "current_pps": pps,
            "current_kbps": kbps,

            # Flow Aggregation Counters
            "flows_created": self.flows_completed + active_flow_cnt,
            "flows_completed": self.flows_completed,
            "active_flows": active_flow_cnt,

            # Threat Detection Verdicts (Separate from Capture Health)
            "threats_detected": self.threats_detected,
            "alerts_generated": self.threats_detected,
            "threat_counts": dict(self.threat_counts),
            "last_threat_timestamp": self.last_threat_timestamp,

            # Local Metadata Queue Metrics
            "queue_pending": queue_stats.get("pending_queue_size", 0),
            "queue_enqueued": queue_stats.get("enqueued_total", 0),
            "queue_dropped": queue_stats.get("dropped_total", 0),
            "queue_spool_size_bytes": queue_stats.get("spool_file_size_bytes", 0)
        }

    def get_recent_events(self, limit: int = 30) -> List[Dict[str, Any]]:
        """Return the most recent live stream events from the ring buffer."""
        return list(self.recent_events)[:limit]
