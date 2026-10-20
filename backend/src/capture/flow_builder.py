"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.capture.flow_builder

Maintains active bidirectional network flow state in memory.
Performs causal packet-to-flow aggregation, timeout tracking, and feature calculation.
Zero payload retention.
"""

import time
import math
import hashlib
import threading
import logging
from pathlib import Path
from typing import Dict, Tuple, Optional, Callable, List, Any
import pandas as pd

from src.capture.flow_schema import FlowRecord

logger = logging.getLogger(__name__)


class _ActiveFlowState:
    """Internal lightweight structure tracking active flow state."""
    __slots__ = (
        'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol',
        'start_time', 'last_seen', 'total_packets', 'total_bytes',
        'forward_packets', 'backward_packets', 'forward_bytes', 'backward_bytes',
        'syn_count', 'ack_count', 'fin_count', 'rst_count', 'psh_count', 'urg_count',
        'packet_timestamps'
    )

    def __init__(self, src_ip: str, dst_ip: str, src_port: Optional[int], dst_port: Optional[int], protocol: str, start_time: float):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.protocol = protocol
        self.start_time = start_time
        self.last_seen = start_time
        
        # Deterministic flow ID from initial 5-tuple and millisecond timestamp
        raw_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}#{protocol}@{int(start_time * 1000)}"
        hash_digest = hashlib.sha256(raw_key.encode('utf-8')).hexdigest()[:16]
        self.flow_id = f"flow_{protocol.lower()}_{hash_digest}"

        self.total_packets = 0
        self.total_bytes = 0
        self.forward_packets = 0
        self.backward_packets = 0
        self.forward_bytes = 0
        self.backward_bytes = 0

        self.syn_count = 0
        self.ack_count = 0
        self.fin_count = 0
        self.rst_count = 0
        self.psh_count = 0
        self.urg_count = 0

        # Compact timestamp list for IAT computation (bounded to at most 1000 timestamps for memory safety)
        self.packet_timestamps: List[float] = [start_time]

    def add_packet(self, timestamp: float, byte_len: int, is_forward: bool, tcp_flags: Optional[Dict[str, bool]] = None):
        """Update flow state with a new packet observation."""
        self.last_seen = timestamp
        self.total_packets += 1
        self.total_bytes += byte_len

        if is_forward:
            self.forward_packets += 1
            self.forward_bytes += byte_len
        else:
            self.backward_packets += 1
            self.backward_bytes += byte_len

        if tcp_flags:
            if tcp_flags.get('SYN'): self.syn_count += 1
            if tcp_flags.get('ACK'): self.ack_count += 1
            if tcp_flags.get('FIN'): self.fin_count += 1
            if tcp_flags.get('RST'): self.rst_count += 1
            if tcp_flags.get('PSH'): self.psh_count += 1
            if tcp_flags.get('URG'): self.urg_count += 1

        if len(self.packet_timestamps) < 1000:
            self.packet_timestamps.append(timestamp)

    def finalize(self) -> FlowRecord:
        """Calculate derived flow features and return a finalized immutable FlowRecord."""
        duration = max(0.0, self.last_seen - self.start_time)
        
        # Safe Rates
        if duration > 0:
            packets_per_second = self.total_packets / duration
            bytes_per_second = self.total_bytes / duration
        else:
            packets_per_second = float(self.total_packets)
            bytes_per_second = float(self.total_bytes)

        # Safe Volumetric Ratios
        tot_pkts = max(1, self.total_packets)
        tot_bytes = max(1, self.total_bytes)

        forward_packet_ratio = self.forward_packets / tot_pkts
        backward_packet_ratio = self.backward_packets / tot_pkts
        forward_byte_ratio = self.forward_bytes / tot_bytes
        backward_byte_ratio = self.backward_bytes / tot_bytes
        bytes_per_packet = self.total_bytes / tot_pkts
        packets_per_byte = self.total_packets / tot_bytes

        # IAT Statistics
        iat_mean = 0.0
        iat_std = 0.0
        iat_min = 0.0
        iat_max = 0.0

        if len(self.packet_timestamps) > 1:
            iats = [
                max(0.0, self.packet_timestamps[i] - self.packet_timestamps[i - 1])
                for i in range(1, len(self.packet_timestamps))
            ]
            if iats:
                iat_mean = float(sum(iats) / len(iats))
                iat_min = float(min(iats))
                iat_max = float(max(iats))
                if len(iats) > 1:
                    variance = sum((x - iat_mean) ** 2 for x in iats) / (len(iats) - 1)
                    iat_std = float(math.sqrt(max(0.0, variance)))

        return FlowRecord(
            flow_id=self.flow_id,
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            src_port=self.src_port,
            dst_port=self.dst_port,
            protocol=self.protocol,
            start_time=self.start_time,
            last_seen=self.last_seen,
            duration=duration,
            total_packets=self.total_packets,
            total_bytes=self.total_bytes,
            forward_packets=self.forward_packets,
            backward_packets=self.backward_packets,
            forward_bytes=self.forward_bytes,
            backward_bytes=self.backward_bytes,
            packets_per_second=packets_per_second,
            bytes_per_second=bytes_per_second,
            forward_packet_ratio=forward_packet_ratio,
            backward_packet_ratio=backward_packet_ratio,
            forward_byte_ratio=forward_byte_ratio,
            backward_byte_ratio=backward_byte_ratio,
            bytes_per_packet=bytes_per_packet,
            packets_per_byte=packets_per_byte,
            syn_count=self.syn_count,
            ack_count=self.ack_count,
            fin_count=self.fin_count,
            rst_count=self.rst_count,
            psh_count=self.psh_count,
            urg_count=self.urg_count,
            iat_mean=iat_mean,
            iat_std=iat_std,
            iat_min=iat_min,
            iat_max=iat_max
        )


class FlowBuilder:
    """
    Online stateful flow aggregation engine.
    Constructs bidirectional flow records from streaming packet metadata.
    """
    def __init__(
        self,
        timeout_seconds: float = 60.0,
        flush_interval_seconds: float = 5.0,
        consumer_callback: Optional[Callable[[FlowRecord], None]] = None,
        jsonl_path: Optional[Path] = None,
        csv_path: Optional[Path] = None,
        max_active_flows: int = 50000
    ):
        self.timeout_seconds = timeout_seconds
        self.flush_interval_seconds = flush_interval_seconds
        self.consumer_callback = consumer_callback
        self.jsonl_path = Path(jsonl_path) if jsonl_path else None
        self.csv_path = Path(csv_path) if csv_path else None
        self.max_active_flows = max_active_flows

        self._active_flows: Dict[Tuple[str, str, Optional[int], Optional[int], str], _ActiveFlowState] = {}
        # Reverse key index for O(1) lookup of backward packets
        self._reverse_index: Dict[Tuple[str, str, Optional[int], Optional[int], str], Tuple[str, str, Optional[int], Optional[int], str]] = {}
        
        self._lock = threading.Lock()
        self._last_flush_time: Optional[float] = None
        self._completed_flows_count = 0
        self._total_packets_processed = 0

        # Ensure output directories exist
        if self.jsonl_path:
            self.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
        if self.csv_path:
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def active_flow_count(self) -> int:
        """Return the number of currently active flows in memory."""
        with self._lock:
            return len(self._active_flows)

    @property
    def completed_flow_count(self) -> int:
        """Return the total number of finalized flows emitted so far."""
        return self._completed_flows_count

    def process_packet(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: str,
        byte_len: int,
        tcp_flags: Optional[Dict[str, bool]] = None
    ):
        """
        Process a single packet metadata tuple and route to the appropriate flow.
        """
        with self._lock:
            self._total_packets_processed += 1
            fwd_key = (src_ip, dst_ip, src_port, dst_port, protocol)
            rev_key = (dst_ip, src_ip, dst_port, src_port, protocol)

            # Check if matching forward flow exists
            if fwd_key in self._active_flows:
                flow = self._active_flows[fwd_key]
                flow.add_packet(timestamp, byte_len, is_forward=True, tcp_flags=tcp_flags)
            # Check if matching backward flow exists
            elif rev_key in self._active_flows:
                flow = self._active_flows[rev_key]
                flow.add_packet(timestamp, byte_len, is_forward=False, tcp_flags=tcp_flags)
            elif rev_key in self._reverse_index:
                primary_key = self._reverse_index[rev_key]
                flow = self._active_flows[primary_key]
                flow.add_packet(timestamp, byte_len, is_forward=False, tcp_flags=tcp_flags)
            else:
                # Create new flow
                if len(self._active_flows) >= self.max_active_flows:
                    # Force prune oldest flow if memory cap reached
                    self._evict_oldest_flow_unlocked()

                new_flow = _ActiveFlowState(src_ip, dst_ip, src_port, dst_port, protocol, timestamp)
                new_flow.add_packet(timestamp, byte_len, is_forward=True, tcp_flags=tcp_flags)
                self._active_flows[fwd_key] = new_flow
                self._reverse_index[rev_key] = fwd_key

            # Periodic cleanup check
            if self._last_flush_time is None:
                self._last_flush_time = timestamp
            elif timestamp - self._last_flush_time >= self.flush_interval_seconds:
                self._flush_expired_unlocked(timestamp)

    def _flush_expired_unlocked(self, current_time: float):
        """Evict and finalize flows exceeding the inactivity timeout."""
        self._last_flush_time = current_time
        expired_keys = []

        for key, flow in self._active_flows.items():
            if current_time - flow.last_seen >= self.timeout_seconds:
                expired_keys.append(key)

        for key in expired_keys:
            self._finalize_and_emit_unlocked(key)

    def _evict_oldest_flow_unlocked(self):
        """Evict the single oldest flow to enforce memory safety."""
        if not self._active_flows:
            return
        oldest_key = min(self._active_flows.keys(), key=lambda k: self._active_flows[k].last_seen)
        self._finalize_and_emit_unlocked(oldest_key)

    def _finalize_and_emit_unlocked(self, key: Tuple):
        """Finalize flow, emit to consumers/files, and clean up active memory."""
        flow = self._active_flows.pop(key, None)
        if flow is None:
            return

        # Clean reverse index
        rev_key = (flow.dst_ip, flow.src_ip, flow.dst_port, flow.src_port, flow.protocol)
        self._reverse_index.pop(rev_key, None)

        record = flow.finalize()
        self._completed_flows_count += 1

        # Emit to JSON Lines
        if self.jsonl_path:
            try:
                with open(self.jsonl_path, 'a', encoding='utf-8') as f:
                    f.write(record.to_json() + '\n')
            except Exception as e:
                logger.error(f"Error writing to JSONL {self.jsonl_path}: {e}")

        # Emit to CSV if configured
        if self.csv_path:
            try:
                write_header = not self.csv_path.exists() or self.csv_path.stat().st_size == 0
                df = pd.DataFrame([record.to_dict()])
                df.to_csv(self.csv_path, mode='a', header=write_header, index=False)
            except Exception as e:
                logger.error(f"Error writing to CSV {self.csv_path}: {e}")

        # Callback
        if self.consumer_callback:
            try:
                self.consumer_callback(record)
            except Exception as e:
                logger.error(f"Error in flow consumer callback: {e}")

    def flush_all(self):
        """Finalize and emit all remaining active flows (used on shutdown)."""
        with self._lock:
            keys = list(self._active_flows.keys())
            for key in keys:
                self._finalize_and_emit_unlocked(key)
            logger.info(f"Flushed all remaining active flows. Total completed: {self._completed_flows_count}")
