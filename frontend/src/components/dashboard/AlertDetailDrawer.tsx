import React, { useEffect } from 'react';
import {
  X,
  ShieldAlert,
  ExternalLink,
  Download,
  AlertTriangle,
  Info,
  Server,
  Layers,
  RefreshCw,
  ArrowLeft
} from 'lucide-react';
import type { ThreatAlert } from '../../types/telemetry';

interface AlertDetailDrawerProps {
  alert: ThreatAlert | null;
  isOpen: boolean;
  isLoading?: boolean;
  error?: string | null;
  onRetry?: () => void;
  onClose: () => void;
  onAcknowledge: (alertId: string) => void;
  onMarkReviewed: (alertId: string) => void;
  onViewFlow?: (flowId: string) => void;
}

export const AlertDetailDrawer: React.FC<AlertDetailDrawerProps> = ({
  alert,
  isOpen,
  isLoading = false,
  error = null,
  onRetry,
  onClose,
  onAcknowledge,
  onMarkReviewed,
  onViewFlow
}) => {
  // Handle ESC key to close
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const getSeverityBadge = (sev: string = 'BENIGN') => {
    switch (sev.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-[#FF4D5A]/15 text-[#FF4D5A] border-[#FF4D5A]/40';
      case 'HIGH':
        return 'bg-[#FF8A3D]/15 text-[#FF8A3D] border-[#FF8A3D]/40';
      case 'MEDIUM':
        return 'bg-[#F7B84B]/15 text-[#F7B84B] border-[#F7B84B]/40';
      case 'LOW':
        return 'bg-[#39D7FF]/15 text-[#39D7FF] border-[#39D7FF]/40';
      default:
        return 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/40';
    }
  };

  const getReviewBadge = (status: string = 'UNREVIEWED') => {
    switch (status.toUpperCase()) {
      case 'REVIEWED':
        return 'bg-[#7DDB52]/20 text-[#7DDB52] border-[#7DDB52]/40';
      case 'ACKNOWLEDGED':
        return 'bg-[#39D7FF]/20 text-[#39D7FF] border-[#39D7FF]/40';
      default:
        return 'bg-[#F7B84B]/20 text-[#F7B84B] border-[#F7B84B]/40';
    }
  };

  const exportAlertJson = () => {
    if (!alert) return;
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alert, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `${alert.alert_id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex justify-end bg-black/60 backdrop-blur-sm transition-opacity animate-in fade-in"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
      role="dialog"
      aria-modal="true"
    >
      <div
        className="w-full max-w-2xl bg-[#07072B] border-l border-[#242452] h-full overflow-y-auto flex flex-col justify-between shadow-2xl p-6 sm:p-8"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Top Header */}
        <div>
          <div className="flex items-center justify-between pb-4 border-b border-[#242452]">
            <div className="flex items-center gap-3 min-w-0">
              <button
                onClick={onClose}
                className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all cursor-pointer flex items-center gap-1 text-xs font-mono shrink-0"
                title="Back to previous view"
              >
                <ArrowLeft className="w-4 h-4" />
                <span className="hidden sm:inline">Back</span>
              </button>

              <div className="w-10 h-10 rounded-xl bg-[#10103D] border border-[#242452] flex items-center justify-center shrink-0">
                <ShieldAlert className="w-5 h-5 text-[#A8F500]" />
              </div>
              <div className="min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-heading font-extrabold text-lg text-[#F5F5F7]">
                    Alert Inspection
                  </span>
                  {alert && (
                    <>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-bold ${getSeverityBadge(alert.severity)}`}>
                        {alert.severity}
                      </span>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${getReviewBadge(alert.review_status)}`}>
                        {alert.review_status || 'UNREVIEWED'}
                      </span>
                    </>
                  )}
                </div>
                {alert && (
                  <span className="text-xs font-mono text-[#A5A5BE] block truncate" title={alert.alert_id}>
                    {alert.alert_id}
                  </span>
                )}
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all cursor-pointer shrink-0 ml-2"
              aria-label="Close alert inspection"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Loading State */}
          {isLoading && (
            <div className="py-20 flex flex-col items-center justify-center text-center font-mono">
              <RefreshCw className="w-8 h-8 text-[#39D7FF] animate-spin mb-4" />
              <p className="text-sm font-semibold text-[#F5F5F7]">
                Retrieving Alert Telemetry & Evidence...
              </p>
              <p className="text-xs text-[#A5A5BE] mt-1 max-w-sm">
                Fetching explainable ML detection evidence and network flow metadata from backend database.
              </p>
            </div>
          )}

          {/* Error State */}
          {!isLoading && error && (
            <div className="my-8 p-6 rounded-2xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 text-center font-mono space-y-3">
              <AlertTriangle className="w-10 h-10 text-[#FF4D5A] mx-auto opacity-80" />
              <h4 className="text-sm font-bold text-[#F5F5F7]">
                Unable to Load Alert Record
              </h4>
              <p className="text-xs text-[#FF4D5A]/90 max-w-md mx-auto">
                {error}
              </p>
              <div className="pt-3 flex items-center justify-center gap-3">
                {onRetry && (
                  <button
                    onClick={onRetry}
                    className="px-4 py-2 rounded-xl bg-[#FF4D5A]/20 hover:bg-[#FF4D5A]/30 border border-[#FF4D5A]/40 text-[#F5F5F7] text-xs font-bold transition-all cursor-pointer flex items-center gap-1.5"
                  >
                    <RefreshCw className="w-3.5 h-3.5" />
                    <span>Retry Request</span>
                  </button>
                )}
                <button
                  onClick={onClose}
                  className="px-4 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] text-xs transition-all cursor-pointer"
                >
                  Return to Dashboard
                </button>
              </div>
            </div>
          )}

          {/* Loaded Alert Details */}
          {!isLoading && !error && alert && (
            <>
              {/* Traffic Context Banner */}
              <div className="mt-4 p-3 rounded-xl bg-[#10103D] border border-[#242452] flex flex-col sm:flex-row sm:items-center justify-between text-xs font-mono gap-2">
                <div className="flex items-center gap-2 text-[#39D7FF]">
                  <Info className="w-4 h-4 shrink-0" />
                  <span>
                    {alert.traffic_context === 'UNLABELED_LIVE'
                      ? 'Real-Time Ingress Telemetry • Read-Only Passive Sensor'
                      : 'Benchmark Evaluation Capture • Ground-Truth Evaluated'}
                  </span>
                </div>
                <span className="text-[10px] text-[#A5A5BE] font-mono truncate" title={alert.flow_id}>
                  Flow: {alert.flow_id ? `${alert.flow_id.slice(0, 16)}...` : 'N/A'}
                </span>
              </div>

              {/* Quick Metrics Grid */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 my-5 text-xs font-mono">
                <div className="p-3 rounded-xl bg-[#10103D]/60 border border-[#242452]">
                  <span className="text-[#A5A5BE] block text-[10px] uppercase">Threat Class</span>
                  <span className="text-[#F5F5F7] font-bold text-sm block mt-0.5 truncate" title={alert.threat_class}>
                    {alert.threat_class}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#10103D]/60 border border-[#242452]">
                  <span className="text-[#A5A5BE] block text-[10px] uppercase">Confidence</span>
                  <span className="text-[#A8F500] font-bold text-sm block mt-0.5">
                    {typeof alert.confidence === 'number' ? `${(alert.confidence * 100).toFixed(1)}%` : 'N/A'}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#10103D]/60 border border-[#242452]">
                  <span className="text-[#A5A5BE] block text-[10px] uppercase">Detector</span>
                  <span className="text-[#39D7FF] font-medium text-xs block mt-0.5 truncate" title={alert.detector}>
                    {alert.detector || 'Multi-Threat Engine'}
                  </span>
                </div>

                <div className="p-3 rounded-xl bg-[#10103D]/60 border border-[#242452]">
                  <span className="text-[#A5A5BE] block text-[10px] uppercase">Model Status</span>
                  <span className="text-[#F7B84B] font-medium text-[11px] block mt-0.5 truncate" title={alert.model_status}>
                    {alert.model_status || 'OPERATIONAL'}
                  </span>
                </div>
              </div>

              {/* 5-Tuple Network Context */}
              <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 mb-5">
                <h5 className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider mb-3 flex items-center gap-2">
                  <Server className="w-3.5 h-3.5 text-[#39D7FF]" />
                  5-Tuple Flow Metadata (Zero-Payload Extracted)
                </h5>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
                  <div className="space-y-1">
                    <div className="flex justify-between py-1 border-b border-[#242452]/40">
                      <span className="text-[#A5A5BE]">Source IP:</span>
                      <span className="text-[#F5F5F7] font-semibold">{alert.src_ip}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#242452]/40">
                      <span className="text-[#A5A5BE]">Source Port:</span>
                      <span className="text-[#F5F5F7]">{alert.src_port ?? '—'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#242452]/40">
                      <span className="text-[#A5A5BE]">Protocol:</span>
                      <span className="text-[#39D7FF] font-bold">{alert.protocol}</span>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between py-1 border-b border-[#242452]/40">
                      <span className="text-[#A5A5BE]">Destination IP:</span>
                      <span className="text-[#F5F5F7] font-semibold">{alert.dst_ip}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#242452]/40">
                      <span className="text-[#A5A5BE]">Destination Port:</span>
                      <span className="text-[#F5F5F7]">{alert.dst_port ?? '—'}</span>
                    </div>
                    <div className="flex justify-between py-1 border-b border-[#242452]/40">
                      <span className="text-[#A5A5BE]">Flow Duration:</span>
                      <span className="text-[#F5F5F7]">
                        {typeof alert.flow_duration === 'number' ? `${alert.flow_duration.toFixed(4)}s` : '—'}
                      </span>
                    </div>
                  </div>
                </div>

                <div className="mt-3 pt-2 border-t border-[#242452]/60 flex items-center justify-between text-xs font-mono text-[#A5A5BE]">
                  <span>
                    Packets: <strong className="text-[#F5F5F7]">
                      {alert.total_packets !== undefined && alert.total_packets !== null ? alert.total_packets.toLocaleString() : '—'}
                    </strong>
                  </span>
                  <span>
                    Bytes: <strong className="text-[#F5F5F7]">
                      {alert.total_bytes !== undefined && alert.total_bytes !== null ? `${alert.total_bytes.toLocaleString()} B` : '—'}
                    </strong>
                  </span>
                  {onViewFlow && alert.flow_id && (
                    <button
                      onClick={() => onViewFlow(alert.flow_id)}
                      className="text-[#39D7FF] hover:underline flex items-center gap-1 cursor-pointer"
                    >
                      <span>Inspect Flow</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  )}
                </div>
              </div>

              {/* Explainable Detection Evidence */}
              <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 mb-5">
                <h5 className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider mb-2 flex items-center gap-2">
                  <Layers className="w-3.5 h-3.5 text-[#A8F500]" />
                  Explainable AI Detection Evidence
                </h5>
                <p className="text-xs text-[#A5A5BE] mb-3 font-sans">
                  {alert.evidence_summary || "Telemetry signals evaluated by model inference pipeline."}
                </p>

                {alert.evidence && alert.evidence.length > 0 ? (
                  <div className="space-y-2">
                    {alert.evidence.map((item, idx) => (
                      <div
                        key={idx}
                        className="p-3 rounded-lg bg-[#07072B] border border-[#242452] text-xs font-mono space-y-1"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-[#A8F500] font-bold">{item.feature || 'Model Metric'}</span>
                          <span className="text-[#F5F5F7] font-semibold">
                            {typeof item.value === 'number' ? item.value.toFixed(4) : (item.value ?? '—')}
                          </span>
                        </div>
                        {item.threshold !== null && item.threshold !== undefined && (
                          <div className="text-[11px] text-[#A5A5BE] flex items-center gap-2">
                            <span>Baseline Threshold: <strong>{item.threshold}</strong></span>
                            {item.direction && (
                              <span className="px-1.5 py-0.2 rounded bg-[#FF4D5A]/15 text-[#FF4D5A]">
                                {item.direction} baseline
                              </span>
                            )}
                          </div>
                        )}
                        {item.explanation && (
                          <p className="text-[11px] font-sans text-[#A5A5BE] mt-1">
                            {item.explanation}
                          </p>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-xs font-mono text-[#7DDB52] p-3 rounded-lg bg-[#07072B]">
                    Baseline feature evaluation recorded without explicit anomalous deviations.
                  </div>
                )}
              </div>

              {/* Recommended SOC Action */}
              <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 mb-5">
                <h5 className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider mb-2 flex items-center gap-2">
                  <AlertTriangle className="w-3.5 h-3.5 text-[#F7B84B]" />
                  Recommended SOC Action
                </h5>
                <p className="text-xs font-mono text-[#F5F5F7] bg-[#07072B] p-3 rounded-lg border border-[#242452]">
                  {alert.recommended_action || "Standard monitoring protocol; correlate with border router telemetry and upstream ingress feeds."}
                </p>
              </div>
            </>
          )}
        </div>

        {/* Bottom Actions Bar */}
        {alert && !isLoading && !error && (
          <div className="pt-4 border-t border-[#242452] flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              {alert.review_status !== 'ACKNOWLEDGED' && (
                <button
                  onClick={() => onAcknowledge(alert.alert_id)}
                  className="px-3.5 py-2 rounded-lg text-xs font-mono font-medium text-[#39D7FF] bg-[#39D7FF]/15 hover:bg-[#39D7FF]/25 border border-[#39D7FF]/30 transition-all cursor-pointer"
                >
                  Acknowledge Alert
                </button>
              )}

              {alert.review_status !== 'REVIEWED' && (
                <button
                  onClick={() => onMarkReviewed(alert.alert_id)}
                  className="px-3.5 py-2 rounded-lg text-xs font-mono font-semibold text-[#07072B] bg-[#A8F500] hover:bg-[#B7FF19] transition-all cursor-pointer"
                >
                  Mark as Reviewed
                </button>
              )}
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={exportAlertJson}
                className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all flex items-center gap-1.5 text-xs font-mono cursor-pointer"
                title="Download Alert JSON"
              >
                <Download className="w-3.5 h-3.5" />
                <span>Export JSON</span>
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
