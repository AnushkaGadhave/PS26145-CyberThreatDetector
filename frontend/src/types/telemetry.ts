export type Protocol = 'TCP' | 'UDP' | 'ICMP';

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'BENIGN';

export type ThreatClass =
  | 'DDoS'
  | 'BOTNET_C2'
  | 'RECON_PORTSCAN'
  | 'MULTI_THREAT'
  | 'BENIGN';

export type ModelCompatibilityStatus =
  | 'FULLY_COMPATIBLE'
  | 'PARTIALLY_COMPATIBLE'
  | 'NOT_COMPATIBLE'
  | 'NOT_YET_IMPLEMENTED';

export type AlertReviewStatus = 'UNREVIEWED' | 'ACKNOWLEDGED' | 'REVIEWED';

export type ConfidenceBand = 'HIGH_CONFIDENCE' | 'MEDIUM_CONFIDENCE' | 'LOW_CONFIDENCE' | 'NOT_APPLICABLE';

export type MonitoringState = 'ACTIVE' | 'PAUSED' | 'STOPPED';

export interface EvidenceItem {
  feature: string;
  value: string | number;
  threshold: number | null;
  direction: 'above' | 'below' | null;
  explanation: string;
}

export interface ThreatAlert {
  alert_id: string;
  timestamp: number;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: Protocol;
  threat_class: ThreatClass;
  threat_category: string;
  confidence: number | null;
  confidence_band: ConfidenceBand;
  severity: Severity;
  traffic_context: string;
  detector: string;
  model_status: ModelCompatibilityStatus;
  evidence: EvidenceItem[];
  evidence_summary: string;
  flow_duration?: number | null;
  total_packets?: number | null;
  total_bytes?: number | null;
  recommended_action?: string;
  review_status?: AlertReviewStatus;
  reviewed_at?: number;
  reviewed_by?: string;
  is_simulated?: boolean;
}

export interface NetworkFlow {
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: Protocol;
  start_time: number;
  last_seen: number;
  duration: number;
  total_packets: number;
  total_bytes: number;
  forward_packets: number;
  backward_packets: number;
  forward_bytes: number;
  backward_bytes: number;
  packets_per_second: number;
  bytes_per_second: number;
  forward_packet_ratio: number;
  backward_packet_ratio: number;
  forward_byte_ratio: number;
  backward_byte_ratio: number;
  bytes_per_packet: number;
  packets_per_byte: number;
  syn_count: number;
  ack_count: number;
  fin_count: number;
  rst_count: number;
  psh_count: number;
  urg_count: number;
  iat_mean: number;
  iat_std: number;
  iat_min: number;
  iat_max: number;
  traffic_context: string;
  detection_outcome: ThreatClass;
  related_alert_id?: string | null;
}

export interface EvaluationMetric {
  accuracy: number;
  precision: number;
  recall: number;
  f1_score: number;
  roc_auc: number;
  pr_auc?: number;
  fpr?: number;
  tpr?: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
}

export interface DetectionModelInfo {
  id: string;
  name: string;
  family: string;
  architecture: string;
  benchmark_dataset: string;
  status: ModelCompatibilityStatus;
  purpose: string;
  feature_count: number;
  key_features: string[];
  metrics: EvaluationMetric;
  limitations: string[];
  calibration_notes: string;
  operational_recommendation: string;
}

export interface TopTalker {
  ip: string;
  flow_count: number;
  byte_count: number;
  threat_count: number;
  category: 'Internal' | 'External' | 'Gateway' | 'Suspicious';
}

export interface DashboardSummary {
  total_flows: number;
  total_alerts: number;
  high_severity_alerts: number;
  critical_alerts: number;
  active_models: number;
  unlabeled_live_count: number;
  alerts_last_5m: number;
  alerts_last_15m: number;
  severity_distribution: Record<Severity, number>;
  threat_distribution: Record<ThreatClass, number>;
  protocol_distribution: Record<Protocol, number>;
  top_talkers: TopTalker[];
}

export interface LiveStreamEvent {
  id: string;
  timestamp: number;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  protocol: Protocol;
  packets: number;
  bytes: number;
  threat_outcome: ThreatClass;
  severity: Severity;
  alert_id?: string;
}
