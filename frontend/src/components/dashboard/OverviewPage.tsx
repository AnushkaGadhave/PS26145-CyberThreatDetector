import React, { useMemo } from 'react';
import {
  ShieldAlert,
  AlertTriangle,
  Cpu,
  ArrowRight,
  Radio,
  Network
} from 'lucide-react';
import type {
  ThreatAlert,
  NetworkFlow,
  DetectionModelInfo
} from '../../types/telemetry';
import type { DashboardOverviewResponse } from '../../services/api';
import { TimeSeriesChart } from './charts/TimeSeriesChart';
import { DonutChart } from './charts/DonutChart';
import { SeverityBar } from './charts/SeverityBar';

interface OverviewPageProps {
  overview: DashboardOverviewResponse | null;
  recentAlerts: ThreatAlert[];
  flows?: NetworkFlow[];
  models: DetectionModelInfo[];
  onNavigateTab: (tab: string) => void;
  onSelectAlert: (alert: ThreatAlert) => void;
}

export const OverviewPage: React.FC<OverviewPageProps> = ({
  overview,
  recentAlerts,
  flows = [],
  models,
  onNavigateTab,
  onSelectAlert
}) => {
  // Safe fallbacks from real overview
  const totalFlows = overview?.total_flows ?? 0;
  const totalAlerts = overview?.total_alerts ?? 0;
  const criticalCount = overview?.severity_counts?.['CRITICAL'] ?? 0;
  const highCount = overview?.severity_counts?.['HIGH'] ?? 0;
  const alertsLast5m = overview?.alerts_last_5_minutes ?? 0;

  const donutSegments = useMemo(() => [
    { category: 'BOTNET_C2', label: 'Botnet C2', count: overview?.threat_counts?.['BOTNET_C2'] ?? 0, color: '#39D7FF' },
    { category: 'DDoS', label: 'DDoS Floods', count: overview?.threat_counts?.['DDoS'] ?? 0, color: '#FF4D5A' },
    { category: 'RECON_PORTSCAN', label: 'Recon / PortScan', count: overview?.threat_counts?.['RECON_PORTSCAN'] ?? 0, color: '#F7B84B' },
    { category: 'MULTI_THREAT', label: 'Multi-Threat', count: overview?.threat_counts?.['MULTI_THREAT'] ?? 0, color: '#A8F500' },
  ], [overview]);

  const severityDistribution = useMemo(() => ({
    CRITICAL: overview?.severity_counts?.['CRITICAL'] ?? 0,
    HIGH: overview?.severity_counts?.['HIGH'] ?? 0,
    MEDIUM: overview?.severity_counts?.['MEDIUM'] ?? 0,
    LOW: overview?.severity_counts?.['LOW'] ?? 0,
    BENIGN: overview?.severity_counts?.['BENIGN'] ?? 0,
  }), [overview]);

  // Compute real dynamic time-series points from actual flows and alerts
  const timelineData = useMemo(() => {
    if (!flows || flows.length === 0) {
      return [];
    }

    // Sort flows by start_time
    const sorted = [...flows].sort((a, b) => a.start_time - b.start_time);
    const minTime = sorted[0].start_time;
    const maxTime = Math.max(sorted[sorted.length - 1].last_seen, minTime + 1);
    const duration = maxTime - minTime;
    const numBuckets = Math.min(10, Math.max(3, sorted.length));
    const bucketSpan = Math.max(1, duration / numBuckets);

    const buckets = Array.from({ length: numBuckets }, (_, i) => {
      const bStart = minTime + i * bucketSpan;
      const bEnd = bStart + bucketSpan;
      const timeLabel = new Date(bStart * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });

      const flowCount = flows.filter(f => f.start_time >= bStart && f.start_time < bEnd).length;
      const threatCount = recentAlerts.filter(a => a.timestamp >= bStart && a.timestamp < bEnd).length;
      const ppsSum = flows
        .filter(f => f.start_time >= bStart && f.start_time < bEnd)
        .reduce((sum, f) => sum + (f.packets_per_second || 0), 0);

      return {
        time: timeLabel,
        flows: flowCount,
        threats: threatCount,
        pps: Math.round(ppsSum)
      };
    });

    return buckets;
  }, [flows, recentAlerts]);

  // Protocol distribution text
  const protocolText = useMemo(() => {
    if (!overview?.protocol_counts) return 'No protocol telemetry recorded yet';
    const counts = overview.protocol_counts;
    const total = Object.values(counts).reduce((a, b) => a + b, 0);
    if (total === 0) return 'No observed flows yet';
    return Object.entries(counts)
      .map(([proto, c]) => `${proto} (${Math.round((c / total) * 100)}%)`)
      .join(' • ');
  }, [overview]);

  const getSeverityBadge = (sev: string) => {
    switch (sev) {
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

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Banner Notice */}
      <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
        <div className="flex items-center gap-2.5 text-[#39D7FF]">
          <span className="w-2 h-2 rounded-full bg-[#39D7FF] animate-ping" />
          <span>SIH PS 26145 • Operational Telemetry Console Active</span>
          <span className="text-[#A5A5BE] hidden md:inline">|</span>
          <span className="text-[#A5A5BE] hidden md:inline">Passive Ingress Diode (Zero-Transmit Mode)</span>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => onNavigateTab('live-monitor')}
            className="text-[#A8F500] hover:underline flex items-center gap-1 cursor-pointer font-bold"
          >
            <Radio className="w-3.5 h-3.5 animate-pulse" />
            <span>Open Live Stream →</span>
          </button>
        </div>
      </div>

      {/* KPI Stat Cards Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Total Observed Flows */}
        <div className="p-5 rounded-2xl bg-[#10103D]/80 border border-[#242452] shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#A5A5BE] mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Observed Flows</span>
            <Network className="w-4 h-4 text-[#39D7FF]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-heading font-extrabold text-[#F5F5F7]">
              {totalFlows.toLocaleString()}
            </span>
            <span className="text-[11px] font-mono text-[#7DDB52] font-semibold">Realtime Persisted</span>
          </div>
          <div className="mt-3 pt-3 border-t border-[#242452]/60 flex items-center justify-between text-[11px] font-mono text-[#A5A5BE]">
            <span>TCP / UDP / ICMP</span>
            <span className="text-[#39D7FF]">100% Passive</span>
          </div>
        </div>

        {/* Detected Threat Events */}
        <div className="p-5 rounded-2xl bg-[#10103D]/80 border border-[#242452] shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#A5A5BE] mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Detected Threats</span>
            <ShieldAlert className="w-4 h-4 text-[#FF4D5A]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-heading font-extrabold text-[#F5F5F7]">
              {totalAlerts}
            </span>
            <span className="text-[11px] font-mono text-[#FF4D5A] font-semibold">Flagged Events</span>
          </div>
          <div className="mt-3 pt-3 border-t border-[#242452]/60 flex items-center justify-between text-[11px] font-mono text-[#A5A5BE]">
            <span>Velocity (5m)</span>
            <span className="text-[#F7B84B] font-bold">{alertsLast5m} events</span>
          </div>
        </div>

        {/* High Severity / Actionable Alerts */}
        <div className="p-5 rounded-2xl bg-[#10103D]/80 border border-[#242452] shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#A5A5BE] mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Actionable Alerts</span>
            <AlertTriangle className="w-4 h-4 text-[#FF8A3D]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-heading font-extrabold text-[#FF4D5A]">
              {criticalCount + highCount}
            </span>
            <span className="text-[11px] font-mono text-[#A5A5BE]">
              ({criticalCount} Crit, {highCount} High)
            </span>
          </div>
          <div className="mt-3 pt-3 border-t border-[#242452]/60 flex items-center justify-between text-[11px] font-mono text-[#A5A5BE]">
            <span>Triaged</span>
            <span className="text-[#A8F500]">Review Req</span>
          </div>
        </div>

        {/* Active Detection Components */}
        <div className="p-5 rounded-2xl bg-[#10103D]/80 border border-[#242452] shadow-lg flex flex-col justify-between">
          <div className="flex items-center justify-between text-[#A5A5BE] mb-2">
            <span className="text-xs font-mono uppercase tracking-wider">Detection Pipeline</span>
            <Cpu className="w-4 h-4 text-[#A8F500]" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-heading font-extrabold text-[#F5F5F7]">
              {models.length} / 3
            </span>
            <span className="text-[11px] font-mono text-[#A8F500] font-semibold">Loaded</span>
          </div>
          <div className="mt-3 pt-3 border-t border-[#242452]/60 flex items-center justify-between text-[11px] font-mono text-[#A5A5BE]">
            <span>RF • Hybrid PCA • IF</span>
            <button
              onClick={() => onNavigateTab('models')}
              className="text-[#39D7FF] hover:underline"
            >
              Inspect
            </button>
          </div>
        </div>
      </div>

      {/* Middle Charts Section: TimeSeries + Donut */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2">
          {timelineData.length > 0 ? (
            <TimeSeriesChart data={timelineData} />
          ) : (
            <div className="w-full bg-[#10103D]/60 border border-[#242452] rounded-xl p-6 text-center text-[#A5A5BE] font-mono flex flex-col items-center justify-center min-h-[260px]">
              <Network className="w-8 h-8 text-[#39D7FF] mb-2 opacity-50" />
              <p className="text-sm font-semibold text-[#F5F5F7]">No network flows observed yet</p>
              <p className="text-xs text-[#A5A5BE] mt-1 max-w-sm">
                Passive traffic capture will plot the real timeline here as flows are recorded.
              </p>
              <button
                onClick={() => onNavigateTab('live-monitor')}
                className="mt-4 px-3 py-1.5 rounded-lg bg-[#A8F500] hover:bg-[#B7FF19] text-[#07072B] text-xs font-bold font-mono transition-colors cursor-pointer"
              >
                Start Capture in Live Monitor →
              </button>
            </div>
          )}
        </div>
        <div>
          <DonutChart segments={donutSegments} totalLabel="Threat Events" />
        </div>
      </div>

      {/* Severity Distribution Progress Bar */}
      <div>
        <SeverityBar distribution={severityDistribution} />
      </div>

      {/* Bottom Split: Recent Alerts Table + Top Communicating Talkers */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Alerts (2 Cols) */}
        <div className="lg:col-span-2 rounded-2xl bg-[#10103D]/60 border border-[#242452] p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h4 className="text-sm font-heading font-semibold text-[#F5F5F7]">
                  Recent Security Events
                </h4>
                <p className="text-[11px] text-[#A5A5BE]">
                  Latest detected threat anomalies awaiting SOC analyst review
                </p>
              </div>

              <button
                onClick={() => onNavigateTab('alerts')}
                className="text-xs font-mono text-[#A8F500] hover:text-[#B7FF19] flex items-center gap-1 cursor-pointer font-bold"
              >
                <span>View All Alerts</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {recentAlerts.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead>
                    <tr className="border-b border-[#242452] text-[#A5A5BE] text-[11px]">
                      <th className="py-2.5 px-3">Alert ID</th>
                      <th className="py-2.5 px-3">Threat</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Source → Target</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#242452]/50">
                    {recentAlerts.slice(0, 5).map((alt) => (
                      <tr
                        key={alt.alert_id}
                        className="hover:bg-[#15154A]/40 transition-colors cursor-pointer group"
                        onClick={() => onSelectAlert(alt)}
                      >
                        <td className="py-3 px-3 text-[#39D7FF] font-semibold truncate max-w-[120px]">
                          {alt.alert_id}
                        </td>
                        <td className="py-3 px-3">
                          <span className="font-semibold text-[#F5F5F7]">
                            {alt.threat_class}
                          </span>
                        </td>
                        <td className="py-3 px-3">
                          <span className={`text-[10px] px-2 py-0.5 rounded border font-bold ${getSeverityBadge(alt.severity)}`}>
                            {alt.severity}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-[#A5A5BE]">
                          {alt.src_ip} → {alt.dst_ip}
                        </td>
                        <td className="py-3 px-3">
                          <span className="text-[10px] text-[#A5A5BE]">
                            {alt.review_status}
                          </span>
                        </td>
                        <td className="py-3 px-3 text-right">
                          <span className="text-[#39D7FF] group-hover:underline text-[11px]">
                            Inspect →
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="py-12 text-center text-[#A5A5BE] font-mono border border-dashed border-[#242452] rounded-xl">
                <ShieldAlert className="w-6 h-6 text-[#A5A5BE] mx-auto mb-2 opacity-40" />
                <p className="text-xs font-semibold text-[#F5F5F7]">No threat alerts recorded yet</p>
                <p className="text-[11px] text-[#A5A5BE] mt-0.5">
                  Flows evaluated by ML models will appear here if malicious or anomalous patterns are identified.
                </p>
              </div>
            )}
          </div>
        </div>

        {/* Top Communicating Talkers (1 Col) */}
        <div className="rounded-2xl bg-[#10103D]/60 border border-[#242452] p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <div>
                <h4 className="text-sm font-heading font-semibold text-[#F5F5F7]">
                  Top Communicators
                </h4>
                <p className="text-[11px] text-[#A5A5BE]">
                  High volume hosts across observed unidirectional ingress
                </p>
              </div>
              <button
                onClick={() => onNavigateTab('flows')}
                className="text-xs font-mono text-[#39D7FF] hover:underline flex items-center gap-1 cursor-pointer"
              >
                <span>Flows</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </button>
            </div>

            {overview?.top_source_ips && overview.top_source_ips.length > 0 ? (
              <div className="space-y-2.5">
                {overview.top_source_ips.slice(0, 5).map((talker) => (
                  <div
                    key={talker.ip}
                    className="p-2.5 rounded-xl bg-[#07072B] border border-[#242452] flex items-center justify-between text-xs font-mono"
                  >
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-[#39D7FF]" />
                      <div>
                        <span className="text-[#F5F5F7] font-semibold block">{talker.ip}</span>
                        <span className="text-[10px] text-[#A5A5BE]">Source Host</span>
                      </div>
                    </div>

                    <div className="text-right">
                      <span className="text-[#A8F500] font-bold block">{talker.count} flows</span>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="py-12 text-center text-[#A5A5BE] font-mono border border-dashed border-[#242452] rounded-xl">
                <p className="text-xs font-semibold text-[#F5F5F7]">No active hosts recorded</p>
                <p className="text-[11px] text-[#A5A5BE] mt-0.5">Awaiting observed traffic</p>
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-[#242452]/60 flex items-center justify-between text-[11px] font-mono text-[#A5A5BE]">
            <span>Protocols: {protocolText}</span>
          </div>
        </div>
      </div>

      {/* Model Health Quick Strip */}
      <div className="rounded-2xl bg-[#10103D]/60 border border-[#242452] p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-4">
          <div>
            <h4 className="text-sm font-heading font-semibold text-[#F5F5F7] flex items-center gap-2">
              <Cpu className="w-4 h-4 text-[#A8F500]" />
              Threat Engine Operational Health
            </h4>
            <p className="text-[11px] text-[#A5A5BE]">
              Runtime compatibility across trained ML & anomaly detection components
            </p>
          </div>

          <button
            onClick={() => onNavigateTab('models')}
            className="text-xs font-mono text-[#A8F500] hover:text-[#B7FF19] flex items-center gap-1 font-bold cursor-pointer"
          >
            <span>Model Details & Limitations</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs font-mono">
          {models.map((m) => (
            <div key={m.id} className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452] flex flex-col justify-between">
              <div>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="font-bold text-[#F5F5F7] truncate" title={m.name}>
                    {m.name}
                  </span>
                  <span className={`text-[10px] px-2 py-0.5 rounded border ${
                    m.status === 'FULLY_COMPATIBLE'
                      ? 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/30'
                      : 'bg-[#F7B84B]/15 text-[#F7B84B] border-[#F7B84B]/30'
                  }`}>
                    {m.status === 'FULLY_COMPATIBLE' ? '100% Compatible' : 'Partial Compat'}
                  </span>
                </div>
                <p className="text-[11px] text-[#A5A5BE] font-sans line-clamp-2">
                  {m.purpose}
                </p>
              </div>

              <div className="mt-3 pt-2 border-t border-[#242452]/40 flex items-center justify-between text-[11px]">
                <span className="text-[#A5A5BE]">Offline F1: <strong className="text-[#A8F500]">{(m.metrics.f1_score * 100).toFixed(2)}%</strong></span>
                <span className="text-[#39D7FF]">{m.feature_count} features</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
