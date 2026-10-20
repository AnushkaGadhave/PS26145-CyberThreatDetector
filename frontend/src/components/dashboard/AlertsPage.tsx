import React, { useState, useMemo } from 'react';
import {
  Search,
  ArrowUpDown,
  ExternalLink,
  AlertTriangle,
  Download,
  Info,
  Check,
  RotateCcw
} from 'lucide-react';
import type { ThreatAlert, Severity, AlertReviewStatus } from '../../types/telemetry';
import { downloadBlob, generateReportFilename, escapeCSVCell } from '../../utils/exportUtils';

interface AlertsPageProps {
  alerts: ThreatAlert[];
  onSelectAlert: (alert: ThreatAlert) => void;
  onAcknowledgeAlert: (alertId: string) => void;
  onMarkReviewedAlert: (alertId: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
}

export const AlertsPage: React.FC<AlertsPageProps> = ({
  alerts,
  onSelectAlert,
  onAcknowledgeAlert,
  onMarkReviewedAlert,
  searchQuery,
  onSearchChange
}) => {
  const [selectedThreat, setSelectedThreat] = useState<string>('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');
  const [sortField, setSortField] = useState<'timestamp' | 'severity' | 'confidence'>('timestamp');
  const [sortAsc, setSortAsc] = useState<boolean>(false);

  // Filter and sort logic
  const filteredAlerts = useMemo(() => {
    return alerts
      .filter((alt) => {
        // Search query
        if (searchQuery.trim()) {
          const q = searchQuery.toLowerCase();
          const matchId = alt.alert_id.toLowerCase().includes(q);
          const matchFlow = alt.flow_id.toLowerCase().includes(q);
          const matchSrc = alt.src_ip.toLowerCase().includes(q);
          const matchDst = alt.dst_ip.toLowerCase().includes(q);
          const matchThreat = alt.threat_class.toLowerCase().includes(q);
          if (!matchId && !matchFlow && !matchSrc && !matchDst && !matchThreat) {
            return false;
          }
        }

        // Threat class
        if (selectedThreat !== 'ALL' && alt.threat_class !== selectedThreat) {
          return false;
        }

        // Severity
        if (selectedSeverity !== 'ALL' && alt.severity !== selectedSeverity) {
          return false;
        }

        // Status
        if (selectedStatus !== 'ALL' && alt.review_status !== selectedStatus) {
          return false;
        }

        return true;
      })
      .sort((a, b) => {
        let compare = 0;
        if (sortField === 'timestamp') {
          compare = a.timestamp - b.timestamp;
        } else if (sortField === 'confidence') {
          compare = (a.confidence || 0) - (b.confidence || 0);
        } else if (sortField === 'severity') {
          const weights: Record<Severity, number> = {
            CRITICAL: 4,
            HIGH: 3,
            MEDIUM: 2,
            LOW: 1,
            BENIGN: 0
          };
          compare = weights[a.severity] - weights[b.severity];
        }
        return sortAsc ? compare : -compare;
      });
  }, [alerts, searchQuery, selectedThreat, selectedSeverity, selectedStatus, sortField, sortAsc]);

  const toggleSort = (field: 'timestamp' | 'severity' | 'confidence') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const resetFilters = () => {
    setSelectedThreat('ALL');
    setSelectedSeverity('ALL');
    setSelectedStatus('ALL');
    onSearchChange('');
  };

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

  const getStatusBadge = (status?: AlertReviewStatus) => {
    switch (status) {
      case 'REVIEWED':
        return 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/30';
      case 'ACKNOWLEDGED':
        return 'bg-[#39D7FF]/15 text-[#39D7FF] border-[#39D7FF]/30';
      default:
        return 'bg-[#F7B84B]/15 text-[#F7B84B] border-[#F7B84B]/30';
    }
  };

  const formatAlertId = (id: string): string => {
    if (!id) return '#unknown';
    const parts = id.split('_');
    if (parts.length >= 4 && parts[0] === 'alert') {
      return `#${parts[2].slice(0, 8)}`;
    }
    if (id.startsWith('alert_')) {
      return `#${id.replace(/^alert_/, '').slice(0, 8)}`;
    }
    return `#${id.slice(0, 8)}`;
  };

  const exportFilteredCSV = () => {
    const headers = ['Alert ID', 'Timestamp', 'Flow ID', 'Source IP', 'Dest IP', 'Protocol', 'Threat Class', 'Severity', 'Confidence', 'Status'];
    const rows = filteredAlerts.map(a => [
      escapeCSVCell(a.alert_id),
      escapeCSVCell(new Date(a.timestamp * 1000).toISOString()),
      escapeCSVCell(a.flow_id),
      escapeCSVCell(`${a.src_ip}:${a.src_port || ''}`),
      escapeCSVCell(`${a.dst_ip}:${a.dst_port || ''}`),
      escapeCSVCell(a.protocol),
      escapeCSVCell(a.threat_class),
      escapeCSVCell(a.severity),
      escapeCSVCell(a.confidence ? `${(a.confidence * 100).toFixed(1)}%` : 'N/A'),
      escapeCSVCell(a.review_status)
    ]);

    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    downloadBlob(blob, generateReportFilename('Threat_Report', 'csv'));
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header & Simulation Disclosure */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-heading font-extrabold text-[#F5F5F7] tracking-tight">
            Threat Alert Management
          </h2>
          <p className="text-xs text-[#A5A5BE] font-mono mt-1">
            Real-time explainable detection verdicts across active detection components
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={exportFilteredCSV}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#F5F5F7] text-xs font-mono font-medium transition-all cursor-pointer"
          >
            <Download className="w-4 h-4 text-[#39D7FF]" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Simulated Distinction Banner */}
      <div className="p-3.5 rounded-xl bg-[#10103D]/60 border border-[#242452] flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 text-[#39D7FF]">
          <Info className="w-4 h-4 shrink-0" />
          <span>
            Showing {filteredAlerts.length} alerts ({alerts.filter(a => a.review_status === 'UNREVIEWED').length} unreviewed)
          </span>
        </div>
        <span className="text-[11px] text-[#A5A5BE]">
          Click any row to open the complete explainable evidence drawer
        </span>
      </div>

      {/* Filter Toolbar */}
      <div className="p-4 rounded-2xl bg-[#10103D]/80 border border-[#242452] shadow-xl space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#A5A5BE]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search alert, flow, IP..."
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl pl-9 pr-3 py-2 text-xs font-mono text-[#F5F5F7] placeholder-[#A5A5BE]/60 focus:outline-none focus:border-[#39D7FF]"
            />
          </div>

          {/* Threat Type Filter */}
          <div>
            <select
              value={selectedThreat}
              onChange={(e) => setSelectedThreat(e.target.value)}
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF]"
            >
              <option value="ALL">All Threat Types</option>
              <option value="BOTNET_C2">Botnet C2</option>
              <option value="DDoS">DDoS Floods</option>
              <option value="RECON_PORTSCAN">Recon / PortScan</option>
              <option value="MULTI_THREAT">Multi-Threat</option>
            </select>
          </div>

          {/* Severity Filter */}
          <div>
            <select
              value={selectedSeverity}
              onChange={(e) => setSelectedSeverity(e.target.value)}
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF]"
            >
              <option value="ALL">All Severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
          </div>

          {/* Review Status Filter */}
          <div className="flex items-center gap-2">
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF]"
            >
              <option value="ALL">All Review Statuses</option>
              <option value="UNREVIEWED">Unreviewed</option>
              <option value="ACKNOWLEDGED">Acknowledged</option>
              <option value="REVIEWED">Reviewed</option>
            </select>

            {(selectedThreat !== 'ALL' || selectedSeverity !== 'ALL' || selectedStatus !== 'ALL' || searchQuery) && (
              <button
                onClick={resetFilters}
                className="p-2 rounded-xl bg-[#07072B] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all cursor-pointer"
                title="Reset all filters"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="rounded-2xl bg-[#10103D]/60 border border-[#242452] overflow-hidden shadow-2xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-[#242452] bg-[#07072B]/60 text-[#A5A5BE] text-[11px]">
                <th
                  className="py-3 px-4 cursor-pointer hover:text-[#F5F5F7] select-none"
                  onClick={() => toggleSort('timestamp')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>Timestamp</span>
                    <ArrowUpDown className="w-3 h-3 opacity-60" />
                  </div>
                </th>
                <th className="py-3 px-4">Alert ID</th>
                <th className="py-3 px-4">Threat Class</th>
                <th
                  className="py-3 px-4 cursor-pointer hover:text-[#F5F5F7] select-none"
                  onClick={() => toggleSort('severity')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>Severity</span>
                    <ArrowUpDown className="w-3 h-3 opacity-60" />
                  </div>
                </th>
                <th
                  className="py-3 px-4 cursor-pointer hover:text-[#F5F5F7] select-none"
                  onClick={() => toggleSort('confidence')}
                >
                  <div className="flex items-center gap-1.5">
                    <span>Confidence</span>
                    <ArrowUpDown className="w-3 h-3 opacity-60" />
                  </div>
                </th>
                <th className="py-3 px-4">Source → Destination</th>
                <th className="py-3 px-4">Protocol</th>
                <th className="py-3 px-4">Review Status</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#242452]/50">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map((alt) => {
                  const dateStr = new Date(alt.timestamp * 1000).toLocaleTimeString();

                  return (
                    <tr
                      key={alt.alert_id}
                      onClick={() => onSelectAlert(alt)}
                      className="hover:bg-[#15154A]/50 transition-colors cursor-pointer group"
                    >
                      <td className="py-3.5 px-4 text-[#A5A5BE] whitespace-nowrap">
                        {dateStr}
                      </td>

                      <td
                        className="py-3.5 px-4 text-[#39D7FF] font-semibold whitespace-nowrap"
                        title={alt.alert_id}
                      >
                        <span className="font-mono">{formatAlertId(alt.alert_id)}</span>
                      </td>

                      <td className="py-3.5 px-4 font-bold text-[#F5F5F7] whitespace-nowrap">
                        {alt.threat_class}
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`text-[10px] px-2 py-0.5 rounded border font-bold ${getSeverityBadge(alt.severity)}`}>
                          {alt.severity}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-[#A8F500] font-semibold whitespace-nowrap">
                        {alt.confidence !== null ? `${(alt.confidence * 100).toFixed(1)}%` : '—'}
                      </td>

                      <td className="py-3.5 px-4 text-[#A5A5BE] whitespace-nowrap">
                        <span className="text-[#F5F5F7] font-semibold">{alt.src_ip}</span>
                        <span className="opacity-40 mx-1.5">→</span>
                        <span>{alt.dst_ip}:{alt.dst_port ?? '—'}</span>
                      </td>

                      <td className="py-3.5 px-4 text-[#39D7FF] font-bold">
                        {alt.protocol}
                      </td>

                      <td className="py-3.5 px-4 whitespace-nowrap">
                        <span className={`text-[10px] px-2 py-0.5 rounded border font-semibold ${getStatusBadge(alt.review_status)}`}>
                          {alt.review_status}
                        </span>
                      </td>

                      <td className="py-3.5 px-4 text-right whitespace-nowrap">
                        <div className="flex items-center justify-end gap-2">
                          {alt.review_status === 'UNREVIEWED' && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onAcknowledgeAlert(alt.alert_id);
                              }}
                              className="px-2 py-1 rounded bg-[#39D7FF]/15 hover:bg-[#39D7FF]/30 text-[#39D7FF] border border-[#39D7FF]/30 text-[10px] font-bold transition-all cursor-pointer"
                              title="Acknowledge Alert"
                            >
                              Ack
                            </button>
                          )}
                          {alt.review_status !== 'REVIEWED' && (
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onMarkReviewedAlert(alt.alert_id);
                              }}
                              className="px-2 py-1 rounded bg-[#A8F500]/15 hover:bg-[#A8F500]/30 text-[#A8F500] border border-[#A8F500]/30 text-[10px] font-bold transition-all cursor-pointer"
                              title="Mark Reviewed"
                            >
                              <Check className="w-3 h-3 inline" />
                            </button>
                          )}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              onSelectAlert(alt);
                            }}
                            className="text-[#39D7FF] hover:underline text-[11px] inline-flex items-center gap-1 cursor-pointer"
                          >
                            <span>Inspect</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={9} className="py-16 text-center text-[#A5A5BE] font-mono">
                    <AlertTriangle className="w-8 h-8 text-[#39D7FF] mx-auto mb-2 opacity-50" />
                    <p className="text-sm font-semibold text-[#F5F5F7]">No threat alerts generated yet</p>
                    <p className="text-xs text-[#A5A5BE] mt-1 max-w-md mx-auto">
                      Real-time passive monitoring has not flagged any malicious anomalies. Alerts will appear here when suspicious flow patterns trigger the ML detectors.
                    </p>
                  </td>
                </tr>
              ) : (
                <tr>
                  <td colSpan={9} className="py-12 text-center text-[#A5A5BE] font-mono">
                    <AlertTriangle className="w-8 h-8 text-[#F7B84B] mx-auto mb-2 opacity-80" />
                    <p className="text-sm font-semibold text-[#F5F5F7]">No matching alerts found</p>
                    <p className="text-xs text-[#A5A5BE] mt-1">Try adjusting search parameters or clearing filters</p>
                    <button
                      onClick={resetFilters}
                      className="mt-3 px-4 py-1.5 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-xs text-[#39D7FF] cursor-pointer"
                    >
                      Clear Filters
                    </button>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
