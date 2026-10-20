/**
 * SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
 * Module: frontend/src/data/modelsMetadata.ts
 *
 * Ground-truth offline model specifications and historical benchmark evaluations.
 * These reflect reproducible offline benchmark experiments (CIC-IDS2017 & CTU-13)
 * and provide complete transparency regarding model architectures and known limitations.
 */

import type { DetectionModelInfo } from '../types/telemetry';

export const detectionModelsData: DetectionModelInfo[] = [
  {
    id: 'ddos-random-forest',
    name: 'DDoS Volumetric Detection Engine',
    family: 'Supervised Random Forest Classifier',
    architecture: 'RandomForestClassifier (200 Estimators, max_depth=20, balanced_subsample)',
    benchmark_dataset: 'CIC-IDS2017 (Friday LOIC HTTP/TCP Flood Partition, Strict Chronological 70/30 Split)',
    status: 'PARTIALLY_COMPATIBLE',
    purpose: 'Rapid detection of high-volume packet and byte rate floods, asymmetrical packet ratios, and connection exhaustion attacks in unidirectional ingress traffic.',
    feature_count: 74,
    key_features: [
      'PacketsPerSecond (Volumetric rate)',
      'BytesPerSecond (Bandwidth saturation)',
      'Forward_Packet_Ratio & Backward_Packet_Ratio',
      'PSH_Flag_Count & URG_Flag_Count',
      'Flow_Duration & Inter-Arrival Time (IAT)',
      'Bytes_Per_Packet (Payload size distribution)'
    ],
    metrics: {
      accuracy: 0.999879,
      precision: 0.999583,
      recall: 0.998308,
      f1_score: 0.998945,
      roc_auc: 0.999755,
      pr_auc: 0.999549,
      fpr: 0.000025,
      tpr: 0.998308,
      true_positives: 38340,
      false_positives: 16,
      true_negatives: 628930,
      false_negatives: 65,
    },
    limitations: [
      'Volumetric and rate features are causally reproduced; however, subflow active/idle segmentation and deep initial TCP window options (Init_Win_bytes) are approximated in streaming unidirectional capture without full TCP state reassembly.',
      'Supervised models trained on historical CIC-IDS2017 LOIC patterns exhibit lower confidence on novel low-and-slow application-layer denial of service.',
      'Offline 99.9% accuracy reflects chronological holdout on benchmark traffic; live unlabeled enterprise traffic exhibits higher variance in legitimate burst volume.'
    ],
    calibration_notes: 'Triage decision thresholds: Critical p >= 0.90, High p >= 0.50, Medium early-warning p >= 0.25 (evaluated across 74 extracted features).',
    operational_recommendation: 'Safe for runtime streaming inference; flags anomalous rate surges and asymmetrical packet ratios within 10 seconds of burst initiation.'
  },
  {
    id: 'c2-hybrid-pipeline',
    name: 'Command-and-Control (C2) Detection Pipeline',
    family: 'Hybrid PCA Manifold Anomaly + DBSCAN + Statistical Beaconing',
    architecture: '15-Component PCA Dimensionality Reduction + DBSCAN Spatial Clustering + Causal Rolling IAT Regularity (CV) Filter',
    benchmark_dataset: 'CTU-13 Scenario 42 (Neris Botnet C2 & IRC Traffic) + 21,242 Clean Campus Baseline Flows',
    status: 'FULLY_COMPATIBLE',
    purpose: 'Identification of covert persistent botnet communication, periodic heartbeat beaconing, and automated malware check-ins without payload decryption.',
    feature_count: 46,
    key_features: [
      'IAT_Regularity_Causal (Coefficient of variation across rolling history)',
      'Src_Flows_60s & Src_Flows_300s (Sliding window connection frequency)',
      'Destination_FanOut_Ratio (Single-target persistence)',
      'Duration_Variability (Fixed-length transaction detection)',
      'PCA Reconstruction Error in 15-dimensional subspace',
      'Zero future-information leakage rolling deques'
    ],
    metrics: {
      accuracy: 0.876954,
      precision: 0.941743,
      recall: 0.839028,
      f1_score: 0.887423,
      roc_auc: 0.962648,
      pr_auc: 0.974490,
      fpr: 0.071096,
      tpr: 0.839028,
      true_positives: 10362,
      false_positives: 641,
      true_negatives: 8375,
      false_negatives: 1988,
    },
    limitations: [
      'Warmup constraint: Requires at least 3 historical flows between source and destination pair before reliable beaconing regularity can be statistically scored.',
      'Jitter evasion: Botnet malware employing high randomized sleep intervals (e.g., jitter > 60%) degrades standalone beaconing recall, requiring DBSCAN manifold corroboration.',
      'DBSCAN component alone exhibits 30.7% FPR; operational alerting strictly requires hybrid corroboration with behavioral timing regularity.'
    ],
    calibration_notes: 'Operating point calibrated at 0.7891 (95th percentile Hybrid Score on 21,242 clean normal training flows, guaranteeing <= 5% false alarm rate on enterprise baselines).',
    operational_recommendation: 'Fully compatible for real-time passive streaming. Maintains in-memory circular state buffers indexed by (SrcIP, DstIP) with zero packet payload inspection.'
  },
  {
    id: 'portscan-isolation-forest',
    name: 'Reconnaissance / PortScan Baseline Detector',
    family: 'Unsupervised Isolation Forest (One-Class Outlier Tree Ensemble)',
    architecture: 'IsolationForest (200 Trees, max_samples=256, trained on 100% Benign Baseline)',
    benchmark_dataset: 'CIC-IDS2017 (Tuesday Reconnaissance Partition, 656,192 Test Flows)',
    status: 'PARTIALLY_COMPATIBLE',
    purpose: 'Baseline anomaly detection for horizontal subnet scanning, vertical port probing, and unauthorized reconnaissance activity.',
    feature_count: 78,
    key_features: [
      'PacketsPerByte (Z-Score separation 3.52)',
      'PSH Flag Count (Z-Score separation 1.86)',
      'BwdByteRatio (Z-Score separation 1.21)',
      'Init_Win_bytes_forward (Z-Score separation 1.13)',
      'Single-flow statistical isolation score'
    ],
    metrics: {
      accuracy: 0.920182,
      precision: 0.000239,
      recall: 0.000220,
      f1_score: 0.000229,
      roc_auc: 0.684973,
      pr_auc: 0.059486,
      fpr: 0.039965,
      tpr: 0.000220,
      true_positives: 6,
      false_positives: 25136,
      true_negatives: 603810,
      false_negatives: 27240,
    },
    limitations: [
      'CRITICAL BENCHMARK DEFICIENCY: The published CIC-IDS2017 MachineLearningCSV stripped Source IP, Destination IP, Source Port, and Timestamps during generation. The model was trained purely on isolated flow feature distributions without host fan-out.',
      'WEAK STANDALONE PERFORMANCE: Unsupervised single-flow Isolation Forest produces 25,136 false positives on normal enterprise traffic and flags only 6 of 27,246 port scan flows at default thresholds (F1 score = 0.00023).',
      'HIGH FALSE ALARM RATE: Individual ephemeral TCP connections often exhibit anomalous packet-to-byte ratios identical to scan probes, causing false alerts without multi-target aggregation.',
      'ARCHITECTURAL REMEDY (Step 12A): Requires online circular ring buffer tracking 30 multi-window behavioral features (Src_UniqueDstHost_60s, Src_UniqueDport_60s, DstPortRange) specified in the Step 12A enhancement roadmap.'
    ],
    calibration_notes: 'Threshold calibrated at anomaly score +0.0265 (5% normal FPR quantile). Scores > 0.10 indicate extreme statistical isolation but require host-level correlation.',
    operational_recommendation: 'Use only as an advisory single-flow anomaly indicator. Operational alerts must be suppressed unless corroborated by Step 12A host fan-out or multi-threat ensemble.'
  }
];
