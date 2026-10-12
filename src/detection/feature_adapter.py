"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.detection.feature_adapter

Translates streaming live FlowRecord objects into compatible numerical feature vectors
for the DDoS (Random Forest), Botnet C2 (Hybrid/PCA), and PortScan (Isolation Forest) models.
"""

import json
import math
import logging
from pathlib import Path
from collections import defaultdict, deque
from typing import Dict, List, Any, Optional, Tuple
import numpy as np
import pandas as pd

from src.capture.flow_schema import FlowRecord

logger = logging.getLogger(__name__)


class FeatureAdapter:
    """
    Stateful and causal feature adapter.
    Maps real-time FlowRecords to model-specific feature matrices.
    """
    def __init__(
        self,
        ddos_config_path: str = "models/ddos/ddos_model_config.json",
        c2_config_path: str = "models/c2/c2_model_config.json",
        portscan_config_path: str = "models/portscan/portscan_model_config.json"
    ):
        # Load feature schemas from model configurations
        self.ddos_features = self._load_feature_list(ddos_config_path)
        self.c2_features = self._load_feature_list(c2_config_path)
        self.portscan_features = self._load_feature_list(portscan_config_path)

        # In-memory causal state tracking for C2 behavioral features
        # src_ip -> deque of (timestamp, dst_ip, dst_port)
        self._src_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=2000))
        # (src_ip, dst_ip) -> deque of timestamps
        self._src_dst_history: Dict[Tuple[str, str], deque] = defaultdict(lambda: deque(maxlen=1000))
        # (src_ip, dst_ip, dst_port) -> count
        self._src_dst_port_counts: Dict[Tuple[str, str, int], int] = defaultdict(int)

    def _load_feature_list(self, config_path: str) -> List[str]:
        """Load feature column list from a JSON model config."""
        p = Path(config_path)
        if p.exists():
            try:
                with open(p, 'r', encoding='utf-8') as f:
                    cfg = json.load(f)
                    return cfg.get('feature_list', cfg.get('features', []))
            except Exception as e:
                logger.error(f"Error loading {config_path}: {e}")
        return []

    def update_history(self, flow: FlowRecord):
        """Update rolling state buffers for causal behavioral metrics."""
        ts = flow.start_time
        src = flow.src_ip
        dst = flow.dst_ip
        dport = flow.dst_port or 0

        self._src_history[src].append((ts, dst, dport))
        self._src_dst_history[(src, dst)].append(ts)
        self._src_dst_port_counts[(src, dst, dport)] += 1

    def to_ddos_dataframe(self, flow: FlowRecord) -> pd.DataFrame:
        """
        Convert a FlowRecord into a single-row DataFrame matching the 74 DDoS model features.
        """
        feat_dict = self._build_cic_feature_dict(flow)
        
        # Build dictionary with exact schema ordering
        row = {}
        for feat in self.ddos_features:
            row[feat] = feat_dict.get(feat, 0.0)
            
        return pd.DataFrame([row], columns=self.ddos_features)

    def to_portscan_dataframe(self, flow: FlowRecord) -> pd.DataFrame:
        """
        Convert a FlowRecord into a single-row DataFrame matching the 78 PortScan model features.
        """
        feat_dict = self._build_cic_feature_dict(flow)

        row = {}
        for feat in self.portscan_features:
            row[feat] = feat_dict.get(feat, 0.0)

        return pd.DataFrame([row], columns=self.portscan_features)

    def to_c2_dataframe(self, flow: FlowRecord) -> pd.DataFrame:
        """
        Convert a FlowRecord and its causal history into a single-row DataFrame matching the 46 C2 features.
        """
        self.update_history(flow)
        c2_dict = self._build_c2_feature_dict(flow)

        row = {}
        for feat in self.c2_features:
            row[feat] = c2_dict.get(feat, 0.0)

        return pd.DataFrame([row], columns=self.c2_features)

    def _build_cic_feature_dict(self, flow: FlowRecord) -> Dict[str, float]:
        """Maps FlowRecord metrics to CIC-IDS2017 feature namespace."""
        dur_micro = flow.duration * 1_000_000.0  # CICFlowMeter uses microseconds
        fwd_pkts = max(1, flow.forward_packets)
        bwd_pkts = max(0, flow.backward_packets)
        tot_pkts = max(1, flow.total_packets)
        tot_bytes = max(1, flow.total_bytes)

        # Mean packet sizes
        avg_pkt_size = flow.bytes_per_packet
        avg_fwd_seg = flow.forward_bytes / fwd_pkts
        avg_bwd_seg = (flow.backward_bytes / bwd_pkts) if bwd_pkts > 0 else 0.0

        # Ratios
        fwd_bwd_pkt_ratio = flow.forward_packets / max(1, flow.backward_packets)
        fwd_bwd_byte_ratio = flow.forward_bytes / max(1, flow.backward_bytes)
        down_up_ratio = flow.backward_packets / fwd_pkts

        # IAT in microseconds
        iat_mean_us = flow.iat_mean * 1_000_000.0
        iat_std_us = flow.iat_std * 1_000_000.0
        iat_max_us = flow.iat_max * 1_000_000.0
        iat_min_us = flow.iat_min * 1_000_000.0

        return {
            'Destination Port': float(flow.dst_port or 0),
            'Flow Duration': float(dur_micro),
            'Total Fwd Packets': float(flow.forward_packets),
            'Total Backward Packets': float(flow.backward_packets),
            'Total Length of Fwd Packets': float(flow.forward_bytes),
            'Total Length of Bwd Packets': float(flow.backward_bytes),
            'Fwd Packet Length Max': float(avg_fwd_seg * 1.5 if flow.forward_packets > 1 else avg_fwd_seg),
            'Fwd Packet Length Min': float(avg_fwd_seg * 0.5 if flow.forward_packets > 1 else avg_fwd_seg),
            'Fwd Packet Length Mean': float(avg_fwd_seg),
            'Fwd Packet Length Std': float(avg_fwd_seg * 0.2 if flow.forward_packets > 1 else 0.0),
            'Bwd Packet Length Max': float(avg_bwd_seg * 1.5 if flow.backward_packets > 1 else avg_bwd_seg),
            'Bwd Packet Length Min': float(avg_bwd_seg * 0.5 if flow.backward_packets > 1 else avg_bwd_seg),
            'Bwd Packet Length Mean': float(avg_bwd_seg),
            'Bwd Packet Length Std': float(avg_bwd_seg * 0.2 if flow.backward_packets > 1 else 0.0),
            'Flow Bytes/s': float(flow.bytes_per_second),
            'Flow Packets/s': float(flow.packets_per_second),
            'Flow IAT Mean': float(iat_mean_us),
            'Flow IAT Std': float(iat_std_us),
            'Flow IAT Max': float(iat_max_us),
            'Flow IAT Min': float(iat_min_us),
            'Fwd IAT Total': float(dur_micro if flow.forward_packets > 1 else 0.0),
            'Fwd IAT Mean': float(iat_mean_us),
            'Fwd IAT Std': float(iat_std_us),
            'Fwd IAT Max': float(iat_max_us),
            'Fwd IAT Min': float(iat_min_us),
            'Bwd IAT Total': float(dur_micro if flow.backward_packets > 1 else 0.0),
            'Bwd IAT Mean': float(iat_mean_us if flow.backward_packets > 1 else 0.0),
            'Bwd IAT Std': float(iat_std_us if flow.backward_packets > 1 else 0.0),
            'Bwd IAT Max': float(iat_max_us if flow.backward_packets > 1 else 0.0),
            'Bwd IAT Min': float(iat_min_us if flow.backward_packets > 1 else 0.0),
            'Fwd PSH Flags': float(1 if flow.psh_count > 0 else 0),
            'Fwd URG Flags': float(1 if flow.urg_count > 0 else 0),
            'Fwd Header Length': float(flow.forward_packets * 20),
            'Bwd Header Length': float(flow.backward_packets * 20),
            'Fwd Packets/s': float(flow.forward_packets / max(0.0001, flow.duration)),
            'Bwd Packets/s': float(flow.backward_packets / max(0.0001, flow.duration)),
            'Min Packet Length': float(min(avg_fwd_seg, avg_bwd_seg) if avg_bwd_seg > 0 else avg_fwd_seg),
            'Max Packet Length': float(max(avg_fwd_seg, avg_bwd_seg)),
            'Packet Length Mean': float(avg_pkt_size),
            'Packet Length Std': float(avg_pkt_size * 0.25 if tot_pkts > 1 else 0.0),
            'Packet Length Variance': float((avg_pkt_size * 0.25) ** 2 if tot_pkts > 1 else 0.0),
            'FIN Flag Count': float(flow.fin_count),
            'SYN Flag Count': float(flow.syn_count),
            'RST Flag Count': float(flow.rst_count),
            'PSH Flag Count': float(flow.psh_count),
            'ACK Flag Count': float(flow.ack_count),
            'URG Flag Count': float(flow.urg_count),
            'CWE Flag Count': 0.0,
            'ECE Flag Count': 0.0,
            'Down/Up Ratio': float(down_up_ratio),
            'Average Packet Size': float(avg_pkt_size),
            'Avg Fwd Segment Size': float(avg_fwd_seg),
            'Avg Bwd Segment Size': float(avg_bwd_seg),
            'Fwd Header Length.1': float(flow.forward_packets * 20),
            'Subflow Fwd Packets': float(flow.forward_packets),
            'Subflow Fwd Bytes': float(flow.forward_bytes),
            'Subflow Bwd Packets': float(flow.backward_packets),
            'Subflow Bwd Bytes': float(flow.backward_bytes),
            'Init_Win_bytes_forward': 8192.0 if flow.protocol == 'TCP' else 0.0,
            'Init_Win_bytes_backward': 8192.0 if flow.protocol == 'TCP' and flow.backward_packets > 0 else 0.0,
            'act_data_pkt_fwd': float(max(0, flow.forward_packets - (1 if flow.syn_count > 0 else 0))),
            'min_seg_size_forward': 20.0 if flow.protocol == 'TCP' else 8.0,
            'Active Mean': float(dur_micro),
            'Active Std': 0.0,
            'Active Max': float(dur_micro),
            'Active Min': float(dur_micro),
            'Idle Mean': 0.0,
            'Idle Std': 0.0,
            'Idle Max': 0.0,
            'Idle Min': 0.0,
            'FwdBwdPacketRatio': float(fwd_bwd_pkt_ratio),
            'FwdBwdByteRatio': float(fwd_bwd_byte_ratio),
            'FwdPacketShare': float(flow.forward_packet_ratio),
            'BwdPacketShare': float(flow.backward_packet_ratio),
            'FwdPacketRatio': float(flow.forward_packet_ratio),
            'BwdPacketRatio': float(flow.backward_packet_ratio),
            'FwdByteRatio': float(flow.forward_byte_ratio),
            'BwdByteRatio': float(flow.backward_byte_ratio),
            'BytesPerPacket': float(flow.bytes_per_packet),
            'PacketsPerByte': float(flow.packets_per_byte)
        }

    def _build_c2_feature_dict(self, flow: FlowRecord) -> Dict[str, float]:
        """Maps FlowRecord and rolling history to CTU-13 causal feature namespace."""
        ts = flow.start_time
        src = flow.src_ip
        dst = flow.dst_ip
        dport = flow.dst_port or 0
        proto = flow.protocol.upper()

        src_events = self._src_history[src]
        src_dst_events = self._src_dst_history[(src, dst)]

        # Window queries
        flows_60s = sum(1 for (t, _, _) in src_events if ts - t <= 60.0)
        flows_300s = sum(1 for (t, _, _) in src_events if ts - t <= 300.0)
        src_dst_60s = sum(1 for t in src_dst_events if ts - t <= 60.0)

        # Unique targets
        unique_dsts = len(set(d for (_, d, _) in src_events))
        unique_dports = len(set(p for (_, _, p) in src_events))

        # IAT calculations on Src-Dst pair
        prev_iats = []
        if len(src_dst_events) > 1:
            events_list = list(src_dst_events)
            prev_iats = [events_list[i] - events_list[i - 1] for i in range(1, len(events_list))]

        iat_cur = prev_iats[-1] if prev_iats else 0.0
        time_since_prev = ts - src_dst_events[-2] if len(src_dst_events) > 1 else 0.0
        iat_mean = float(np.mean(prev_iats)) if prev_iats else 0.0
        iat_std = float(np.std(prev_iats)) if len(prev_iats) > 1 else 0.0
        iat_min = float(np.min(prev_iats)) if prev_iats else 0.0
        iat_max = float(np.max(prev_iats)) if prev_iats else 0.0

        # Causal timing regularity requires at least 2 observed intervals (3 flows)
        if len(prev_iats) >= 2 and iat_mean > 0:
            iat_cv = float(iat_std / iat_mean)
            iat_regularity = float(1.0 / (1.0 + iat_cv))
        else:
            iat_cv = 0.0
            iat_regularity = 0.0  # Cold-start / insufficient interval history

        # Ratios
        tot_src_flows = max(1, len(src_events))
        tot_src_dst_flows = len(src_dst_events)
        repeat_ratio = (tot_src_dst_flows / tot_src_flows) if tot_src_flows > 1 else 0.0
        dst_fanout = unique_dsts / tot_src_flows

        return {
            'Dur': float(flow.duration),
            'sTos': 0.0,
            'dTos': 0.0,
            'TotPkts': float(flow.total_packets),
            'TotBytes': float(flow.total_bytes),
            'SrcBytes': float(flow.forward_bytes),
            'PacketsPerSecond': float(flow.packets_per_second),
            'BytesPerSecond': float(flow.bytes_per_second),
            'SourceBytesPerSecond': float(flow.forward_bytes / max(0.001, flow.duration)),
            'BytesPerPacket': float(flow.bytes_per_packet),
            'PacketsPerByte': float(flow.packets_per_byte),
            'DestinationBytesApprox': float(flow.backward_bytes),
            'SourceByteRatio': float(flow.forward_byte_ratio),
            'Proto_UDP': 1.0 if proto == 'UDP' else 0.0,
            'Proto_TCP': 1.0 if proto == 'TCP' else 0.0,
            'Proto_ICMP': 1.0 if proto == 'ICMP' else 0.0,
            'Dir_Bidirectional': 1.0 if flow.backward_packets > 0 else 0.0,
            'Dir_Unidirectional': 1.0 if flow.backward_packets == 0 else 0.0,
            'Dir_Unknown': 0.0,
            'State_CON': 1.0 if proto == 'UDP' and flow.backward_packets > 0 else (1.0 if flow.syn_count > 0 and flow.ack_count > 0 else 0.0),
            'State_S_': 1.0 if flow.syn_count > 0 and flow.ack_count == 0 else 0.0,
            'State_FSPA_FSPA': 1.0 if flow.fin_count > 0 and flow.psh_count > 0 else 0.0,
            'State_FSA_FSA': 1.0 if flow.fin_count > 0 and flow.syn_count > 0 else 0.0,
            'State_INT': 1.0 if flow.backward_packets == 0 else 0.0,
            'IAT_SrcDst': float(iat_cur),
            'TimeSincePrev_SrcDst': float(time_since_prev),
            'IAT_RunningMean_SrcDst': float(iat_mean),
            'IAT_RunningStd_SrcDst': float(iat_std),
            'IAT_RunningMin_SrcDst': float(iat_min),
            'IAT_RunningMax_SrcDst': float(iat_max),
            'IAT_CV_Causal': float(iat_cv),
            'IAT_Regularity_Causal': float(iat_regularity),
            'Src_Flows_BeforeOrAtT': float(tot_src_flows),
            'Src_UniqueDst_BeforeOrAtT': float(unique_dsts),
            'Src_UniqueDport_BeforeOrAtT': float(unique_dports),
            'SrcDst_Flows_BeforeOrAtT': float(tot_src_dst_flows),
            'SrcDstPort_Flows_BeforeOrAtT': float(self._src_dst_port_counts[(src, dst, dport)]),
            'RepeatRatio_SrcDst_Causal': float(repeat_ratio),
            'Src_Dst_Concentration_Causal': float(repeat_ratio),
            'DstFanoutRatio_Causal': float(dst_fanout),
            'IsRepeatedSrcDst_Causal': 1.0 if tot_src_dst_flows > 1 else 0.0,
            'Src_Flows_60s': float(flows_60s),
            'Src_Flows_300s': float(flows_300s),
            'SrcDst_Flows_60s': float(src_dst_60s),
            'IsHighFrequencySrc_Causal': 1.0 if flows_60s >= 10 else 0.0,
            'IsShortDuration_Causal': 1.0 if flow.duration <= 1.0 else 0.0
        }
