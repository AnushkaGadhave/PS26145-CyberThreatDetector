from typing import Dict, List, Any, Optional, Tuple
from src.capture.flow_schema import FlowRecord
from src.alerts.alert_schema import ThreatEvidenceItem


class EvidenceBuilder:
    """
    Constructs explainable evidence dictionaries for DDoS, C2, and PortScan detections.
    """

    @staticmethod
    def build_ddos_evidence(flow: FlowRecord, probability: float, model_status: str = "PARTIALLY_COMPATIBLE") -> Tuple[List[Dict[str, Any]], str]:
        """Generate supporting evidence items for DDoS detections."""
        items: List[ThreatEvidenceItem] = []

        # 1. Packet rate
        if flow.packets_per_second >= 100.0:
            items.append(ThreatEvidenceItem(
                feature="packets_per_second",
                value=flow.packets_per_second,
                threshold=100.0,
                direction="above",
                explanation=f"High packet transmission rate ({flow.packets_per_second:.1f} pkts/s) indicates potential flooding."
            ))

        # 2. Byte rate
        if flow.bytes_per_second >= 50000.0:
            items.append(ThreatEvidenceItem(
                feature="bytes_per_second",
                value=flow.bytes_per_second,
                threshold=50000.0,
                direction="above",
                explanation=f"Elevated bandwidth consumption ({flow.bytes_per_second:.1f} B/s) observed."
            ))

        # 3. SYN flag activity
        if flow.syn_count >= 5:
            items.append(ThreatEvidenceItem(
                feature="syn_count",
                value=flow.syn_count,
                threshold=5.0,
                direction="above",
                explanation=f"Unusually high SYN flag count ({flow.syn_count}) indicates possible SYN flood."
            ))

        # 4. Asymmetric traffic
        if flow.forward_packet_ratio >= 0.85 and flow.total_packets >= 10:
            items.append(ThreatEvidenceItem(
                feature="forward_packet_ratio",
                value=flow.forward_packet_ratio,
                threshold=0.85,
                direction="above",
                explanation=f"Strong unidirectional packet asymmetry ({flow.forward_packet_ratio * 100:.1f}% forward) without proportional responses."
            ))

        # Model probability
        items.append(ThreatEvidenceItem(
            feature="ddos_model_probability",
            value=probability,
            threshold=0.50,
            direction="above",
            explanation=f"Random Forest DDoS classifier estimated attack probability of {probability:.2%}."
        ))

        # Partial compatibility note if applicable
        if model_status == "PARTIALLY_COMPATIBLE":
            items.append(ThreatEvidenceItem(
                feature="model_compatibility_disclosure",
                value="PARTIALLY_COMPATIBLE",
                threshold=None,
                direction=None,
                explanation="Model/runtime feature compatibility is partial; subflow metrics approximated in lightweight streaming."
            ))

        evidence_list = [item.to_dict() for item in items]
        summary = f"DDoS suspicion (prob={probability:.2%}) supported by {len(items)} volumetric and flag indicators."
        return evidence_list, summary

    @staticmethod
    def build_c2_evidence(flow: FlowRecord, c2_features_dict: Dict[str, Any], score: float, model_status: str = "FULLY_COMPATIBLE") -> Tuple[List[Dict[str, Any]], str]:
        """Generate supporting evidence items for Botnet C2 / Beaconing detections."""
        items: List[ThreatEvidenceItem] = []

        tot_src_dst_flows = c2_features_dict.get('SrcDst_Flows_BeforeOrAtT', 0)
        tot_src_flows = c2_features_dict.get('Src_Flows_BeforeOrAtT', 0)

        # 1. Inter-arrival regularity (only valid with >= 3 observations of pair)
        iat_reg = c2_features_dict.get('IAT_Regularity_Causal', 0.0)
        if tot_src_dst_flows >= 3 and iat_reg >= 0.5:
            items.append(ThreatEvidenceItem(
                feature="IAT_Regularity_Causal",
                value=iat_reg,
                threshold=0.50,
                direction="above",
                explanation=f"High inter-arrival time regularity ({iat_reg:.2f}) indicates automated heartbeat/beaconing."
            ))

        # 2. Connection frequency in 60s
        src_flows_60s = c2_features_dict.get('Src_Flows_60s', 0)
        if tot_src_flows >= 5 and src_flows_60s >= 5:
            items.append(ThreatEvidenceItem(
                feature="Src_Flows_60s",
                value=src_flows_60s,
                threshold=5.0,
                direction="above",
                explanation=f"Source initiated {src_flows_60s} connections within the last 60 seconds."
            ))

        # 3. Repeat communication with target (only valid with >= 3 total source flows)
        repeat_ratio = c2_features_dict.get('RepeatRatio_SrcDst_Causal', 0.0)
        if tot_src_flows >= 3 and repeat_ratio >= 0.5:
            items.append(ThreatEvidenceItem(
                feature="RepeatRatio_SrcDst_Causal",
                value=repeat_ratio,
                threshold=0.50,
                direction="above",
                explanation=f"High destination concentration ({repeat_ratio * 100:.1f}%) targeting {flow.dst_ip}."
            ))

        # 4. Low fanout
        fanout = c2_features_dict.get('DstFanoutRatio_Causal', 1.0)
        if tot_src_flows >= 5 and fanout <= 0.3:
            items.append(ThreatEvidenceItem(
                feature="DstFanoutRatio_Causal",
                value=fanout,
                threshold=0.30,
                direction="below",
                explanation=f"Low target diversity ({fanout:.2f}) indicates persistent dedicated channel."
            ))

        # Model status disclosure if history is insufficient
        if model_status == "INSUFFICIENT_HISTORY" or tot_src_dst_flows < 3:
            items.append(ThreatEvidenceItem(
                feature="causal_history_status",
                value=f"src_dst_observations={tot_src_dst_flows}",
                threshold=3.0,
                direction="below",
                explanation="Insufficient causal history for reliable timing regularity assessment (< 3 observations)."
            ))

        # Anomaly / distance score
        items.append(ThreatEvidenceItem(
            feature="c2_hybrid_score",
            value=score,
            threshold=0.50,
            direction="above" if score >= 0.5 else "below",
            explanation=f"Botnet C2 hybrid PCA/beaconing detector assigned anomaly score of {score:.4f}."
        ))

        evidence_list = [item.to_dict() for item in items]
        if model_status == "INSUFFICIENT_HISTORY" or tot_src_dst_flows < 3:
            summary = f"C2 detector warm-up state: insufficient causal history ({tot_src_dst_flows} obs) for periodicity assessment."
        else:
            summary = f"Botnet C2 suspicion (score={score:.2f}) evaluated across causal history ({tot_src_dst_flows} flows)."
        return evidence_list, summary

    @staticmethod
    def build_portscan_evidence(flow: FlowRecord, anomaly_score: float, threshold: float = 0.026465, model_status: str = "PARTIALLY_COMPATIBLE") -> Tuple[List[Dict[str, Any]], str]:
        """Generate supporting evidence items for Reconnaissance / PortScan detections."""
        items: List[ThreatEvidenceItem] = []

        # 1. Anomaly score vs baseline
        items.append(ThreatEvidenceItem(
            feature="portscan_anomaly_score",
            value=anomaly_score,
            threshold=threshold,
            direction="above" if anomaly_score >= threshold else "below",
            explanation=f"Flow statistical isolation score ({anomaly_score:+.6f}) exceeds 5% normal baseline threshold ({threshold:+.6f})."
        ))

        # 2. High packet to byte ratio (tiny probe packets)
        if flow.packets_per_byte >= 0.01:
            items.append(ThreatEvidenceItem(
                feature="packets_per_byte",
                value=flow.packets_per_byte,
                threshold=0.01,
                direction="above",
                explanation=f"High packet-to-byte ratio ({flow.packets_per_byte:.4f}) characteristic of small port probes."
            ))

        # 3. Probe Flag Activity
        if flow.syn_count > 0 or flow.psh_count > 0:
            items.append(ThreatEvidenceItem(
                feature="probe_tcp_flags",
                value=f"SYN={flow.syn_count}, PSH={flow.psh_count}, ACK={flow.ack_count}",
                threshold=None,
                direction=None,
                explanation=f"Observed TCP control flags consistent with network scanning handshakes."
            ))

        # 4. Short duration
        if flow.duration <= 0.1:
            items.append(ThreatEvidenceItem(
                feature="flow_duration",
                value=flow.duration,
                threshold=0.10,
                direction="below",
                explanation=f"Ultra-short flow duration ({flow.duration:.4f}s) typical of single-shot connection probes."
            ))

        # Partial compatibility note
        if model_status == "PARTIALLY_COMPATIBLE":
            items.append(ThreatEvidenceItem(
                feature="model_compatibility_disclosure",
                value="PARTIALLY_COMPATIBLE",
                threshold=None,
                direction=None,
                explanation="Model/runtime feature compatibility is partial; flow-level IF is an anomaly indicator without host fan-out."
            ))

        evidence_list = [item.to_dict() for item in items]
        summary = f"Reconnaissance anomaly (score={anomaly_score:+.4f}) exceeding normal baseline threshold."
        return evidence_list, summary
