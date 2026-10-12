"""
SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
Module: src.alerts.alert_engine

Central unified threat alert engine.
Applies deterministic severity policies, evidence aggregation, stateful alert suppression,
and generates structured ThreatAlert objects.
"""

import json
import time
import hashlib
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

from src.capture.flow_schema import FlowRecord
from src.alerts.alert_schema import ThreatAlert, DetectorResult
from src.alerts.evidence_builder import EvidenceBuilder
from src.detection.model_status import get_model_status

logger = logging.getLogger(__name__)


class AlertEngine:
    """
    Unified threat evaluation and alert generation engine.
    """
    def __init__(
        self,
        policy_config_path: str = "config/alert_policy.json",
        suppression_window_seconds: float = 30.0,
        mode: str = "ALERT"  # 'ALERT' (suspicious only) or 'AUDIT' (all flows)
    ):
        self.policy_path = Path(policy_config_path)
        self.policy = self._load_policy()
        self.suppression_window_seconds = suppression_window_seconds or self.policy.get("suppression_window_seconds", 30.0)
        self.mode = mode.upper()

        # In-memory deduplication cache: (suppression_key, threat_class) -> last_alert_timestamp
        self._suppression_cache: Dict[Tuple[str, str], float] = {}

        # Alert statistics
        self.total_evaluated = 0
        self.total_alerts_generated = 0
        self.severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "BENIGN": 0
        }
        self.threat_counts = {
            "DDoS": 0,
            "BOTNET_C2": 0,
            "RECON_PORTSCAN": 0,
            "MULTI_THREAT": 0,
            "BENIGN": 0
        }

    def _load_policy(self) -> Dict[str, Any]:
        """Load centralized alert policy configuration."""
        if self.policy_path.exists():
            try:
                with open(self.policy_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load alert policy {self.policy_path}: {e}")
        return {
            "suppression_window_seconds": 30.0,
            "threat_categories": {
                "DDoS": {"critical_probability_threshold": 0.90, "high_probability_threshold": 0.50},
                "BOTNET_C2": {"critical_probability_threshold": 0.85, "high_probability_threshold": 0.50, "medium_probability_threshold": 0.30},
                "RECON_PORTSCAN": {"anomaly_score_threshold": 0.026465, "high_anomaly_score_threshold": 0.10}
            }
        }

    def is_suppressed(self, flow: FlowRecord, threat_class: str) -> bool:
        """
        Check if an alert for this flow / source-destination pair and threat class is currently suppressed.
        """
        key = (f"{flow.src_ip}->{flow.dst_ip}:{flow.dst_port}", threat_class)
        now = flow.last_seen or time.time()
        last_time = self._suppression_cache.get(key)

        if last_time is not None and (now - last_time) < self.suppression_window_seconds:
            return True

        self._suppression_cache[key] = now
        return False

    def evaluate_detector_results(
        self,
        flow: FlowRecord,
        results: List[DetectorResult],
        traffic_context: Optional[str] = None
    ) -> Optional[ThreatAlert]:
        """
        Aggregates multiple detector results into a unified ThreatAlert.
        Applies calibrated severity assignment, evidence extraction, confidence banding,
        and stateful alert deduplication.
        """
        self.total_evaluated += 1
        model_statuses = get_model_status()
        t_ctx = traffic_context or self.policy.get("traffic_context_default", "UNLABELED_LIVE")

        active_threats: List[str] = []
        all_evidence: List[Dict[str, Any]] = []
        evidence_summaries: List[str] = []
        highest_confidence: Optional[float] = None
        max_anomaly_score: float = 0.0
        detectors_triggered: List[str] = []
        triggered_results: List[DetectorResult] = []

        # Process each individual detector result
        for res in results:
            # Check warm-up / insufficient history
            if res.status == "INSUFFICIENT_HISTORY" or res.compatible == "INSUFFICIENT_HISTORY":
                logger.debug(f"Detector {res.detector} reported INSUFFICIENT_HISTORY; skipping alert generation.")
                continue

            # Check model compatibility
            mod_key = res.threat_class.lower().replace("recon_", "").replace("botnet_", "")
            compat_info = model_statuses.get(mod_key, {})
            compat_status = compat_info.get("status", res.compatible)

            if compat_status == "NOT_COMPATIBLE":
                logger.warning(f"Detection from incompatible model {res.detector} ignored for live alerting.")
                continue

            if res.prediction == 1:
                # Assign confidence band to detector result
                if res.confidence is not None:
                    if res.confidence >= 0.85:
                        res.confidence_band = "HIGH_CONFIDENCE"
                    elif res.confidence >= 0.50:
                        res.confidence_band = "MEDIUM_CONFIDENCE"
                    else:
                        res.confidence_band = "LOW_CONFIDENCE"
                else:
                    # Continuous anomaly scores (like Isolation Forest) are low-confidence single-flow indicators
                    res.confidence_band = "LOW_CONFIDENCE"

                active_threats.append(res.threat_class)
                detectors_triggered.append(res.detector)
                triggered_results.append(res)
                all_evidence.extend(res.evidence)
                if res.reason:
                    evidence_summaries.append(res.reason)

                if res.confidence is not None:
                    if highest_confidence is None or res.confidence > highest_confidence:
                        highest_confidence = res.confidence
                if res.score is not None and res.score > max_anomaly_score:
                    max_anomaly_score = res.score

        # Determine Unified Threat Class, Confidence Band, and Severity Triage
        if not active_threats:
            threat_class = "BENIGN"
            threat_category = "BENIGN"
            severity = "BENIGN"
            confidence_band = "NOT_APPLICABLE"
            rec_action = "Standard telemetry monitoring; no anomaly observed."
            evidence_summary = "All threat detectors reported normal baseline flow characteristics."
            primary_detector = "MultiThreatEnsemble"
            overall_model_status = "FULLY_COMPATIBLE"
            highest_confidence = None

        elif len(active_threats) > 1:
            threat_class = "MULTI_THREAT"
            threat_category = ", ".join(active_threats)
            primary_detector = "+".join(detectors_triggered)
            overall_model_status = "PARTIALLY_COMPATIBLE" if any("PARTIAL" in r.compatible for r in triggered_results) else "FULLY_COMPATIBLE"

            # Multi-threat triage: check if any detector has high or medium confidence
            has_high = any(r.confidence_band == "HIGH_CONFIDENCE" for r in triggered_results)
            med_count = sum(1 for r in triggered_results if r.confidence_band == "MEDIUM_CONFIDENCE")

            if t_ctx == "UNLABELED_LIVE":
                if has_high:
                    severity = "HIGH"
                    confidence_band = "HIGH_CONFIDENCE"
                elif med_count >= 2:
                    severity = "MEDIUM"
                    confidence_band = "MEDIUM_CONFIDENCE"
                else:
                    # Weak multi-anomaly in unlabeled live traffic does NOT escalate to CRITICAL
                    severity = "LOW"
                    confidence_band = "LOW_CONFIDENCE"
                rec_action = "Review multi-model suspicious indicators; correlate with endpoint DNS and application logs."
                evidence_summary = "Multiple model suspicions on unlabeled live traffic: " + ", ".join(evidence_summaries)
            else:
                if has_high:
                    severity = "CRITICAL"
                    confidence_band = "HIGH_CONFIDENCE"
                else:
                    severity = "HIGH"
                    confidence_band = "MEDIUM_CONFIDENCE"
                rec_action = "High priority: Correlate multi-threat indicators across host connection history."
                evidence_summary = "Multiple concurrent threats detected on the same network flow: " + ", ".join(evidence_summaries)

        else:
            threat_class = active_threats[0]
            threat_category = threat_class
            primary_detector = detectors_triggered[0]
            single_res = triggered_results[0]
            overall_model_status = single_res.compatible
            confidence_band = single_res.confidence_band

            # Determine severity for single threat
            if threat_class == "DDoS":
                ddos_prob = highest_confidence or 0.0
                if ddos_prob >= 0.90:
                    severity = "CRITICAL"
                    confidence_band = "HIGH_CONFIDENCE"
                elif ddos_prob >= 0.50:
                    severity = "HIGH" if t_ctx != "UNLABELED_LIVE" else "MEDIUM"
                    confidence_band = "MEDIUM_CONFIDENCE"
                else:
                    severity = "LOW"
                    confidence_band = "LOW_CONFIDENCE"
                rec_action = "Monitor source IP volumetric packet/byte rates; check server ingress load."

            elif threat_class == "BOTNET_C2":
                c2_score = highest_confidence or max_anomaly_score
                if c2_score >= 0.85:
                    severity = "HIGH" if t_ctx == "UNLABELED_LIVE" else "CRITICAL"
                    confidence_band = "HIGH_CONFIDENCE"
                elif c2_score >= 0.50:
                    severity = "MEDIUM" if t_ctx == "UNLABELED_LIVE" else "HIGH"
                    confidence_band = "MEDIUM_CONFIDENCE"
                else:
                    severity = "LOW"
                    confidence_band = "LOW_CONFIDENCE"
                rec_action = "Review destination IP in DNS history and threat intelligence feeds; inspect periodic timing."

            elif threat_class == "RECON_PORTSCAN":
                # Single-flow IF is a weak anomaly indicator in live traffic
                if t_ctx == "UNLABELED_LIVE":
                    severity = "LOW"
                    confidence_band = "LOW_CONFIDENCE"
                else:
                    severity = "MEDIUM"
                    confidence_band = "LOW_CONFIDENCE"
                rec_action = "Review destination port diversity for source IP across local subnet; correlate firewall logs."

            else:
                severity = "LOW"
                confidence_band = "LOW_CONFIDENCE"
                rec_action = "Review anomalous connection attributes in security logs."

            prefix = "Model suspicion on unlabeled live traffic" if t_ctx == "UNLABELED_LIVE" else f"{threat_class} detected"
            evidence_summary = "; ".join(evidence_summaries) if evidence_summaries else f"{prefix}: baseline threshold exceeded."

        # Update stats
        self.severity_counts[severity] = self.severity_counts.get(severity, 0) + 1
        self.threat_counts[threat_class] = self.threat_counts.get(threat_class, 0) + 1

        # In ALERT mode, suppress benign flows unless AUDIT mode is enabled
        if self.mode == "ALERT" and severity == "BENIGN":
            return None

        # Check deduplication suppression for threat alerts
        if severity != "BENIGN" and self.is_suppressed(flow, threat_class):
            logger.debug(f"Suppressed duplicate alert for {flow.src_ip}->{flow.dst_ip} ({threat_class})")
            return None

        # Generate deterministic unique alert ID
        raw_id_str = f"{flow.flow_id}_{threat_class}_{int(flow.start_time * 1000)}"
        alert_hash = hashlib.sha256(raw_id_str.encode('utf-8')).hexdigest()[:12]
        alert_id = f"alert_{int(flow.start_time)}_{alert_hash}_{threat_class.lower()}"

        alert = ThreatAlert(
            alert_id=alert_id,
            timestamp=flow.start_time,
            flow_id=flow.flow_id,
            src_ip=flow.src_ip,
            dst_ip=flow.dst_ip,
            src_port=flow.src_port,
            dst_port=flow.dst_port,
            protocol=flow.protocol,
            threat_class=threat_class,
            threat_category=threat_category,
            confidence=highest_confidence if highest_confidence is not None else (round(max_anomaly_score, 4) if max_anomaly_score > 0 else None),
            confidence_band=confidence_band,
            severity=severity,
            traffic_context=t_ctx,
            detector=primary_detector,
            model_status=overall_model_status,
            evidence=all_evidence,
            evidence_summary=evidence_summary,
            flow_duration=flow.duration,
            total_packets=flow.total_packets,
            total_bytes=flow.total_bytes,
            recommended_action=rec_action
        )

        self.total_alerts_generated += 1
        return alert
