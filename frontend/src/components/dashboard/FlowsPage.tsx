import React, { useState, useMemo } from 'react';
import {
  Search,
  Network,
  ExternalLink,
  ShieldAlert,
  RotateCcw,
  Download,
  Info,
  RefreshCw
} from 'lucide-react';
import type { NetworkFlow } from '../../types/telemetry';

interface FlowsPageProps {
  flows: NetworkFlow[];
  onSelectFlow: (flow: NetworkFlow) => void;
  onNavigateToAlert?: (alertId: string) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
}

export const FlowsPage: React.FC<FlowsPageProps> = ({
  flows,
  onSelectFlow,
  onNavigateToAlert,
  searchQuery,
  onSearchChange
}) => {
  const [selectedProto, setSelectedProto] = useState<string>('ALL');
  const [selectedOutcome, setSelectedOutcome] = useState<string>('ALL');
  const [minPackets, setMinPackets] = useState<number>(0);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [simulateError, setSimulateError] = useState<boolean>(false);

  const filteredFlows = useMemo(() => {
    return flows.filter((f) => {
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const matchId = f.flow_id.toLowerCase().includes(q);
        const matchSrc = f.src_ip.toLowerCase().includes(q);
        const matchDst = f.dst_ip.toLowerCase().includes(q);
        if (!matchId && !matchSrc && !matchDst) {
          return false;
        }
      }

      if (selectedProto !== 'ALL' && f.protocol !== selectedProto) {
        return false;
      }

      if (selectedOutcome === 'THREAT' && f.detection_outcome === 'BENIGN') {
        return false;
      }
      if (selectedOutcome === 'BENIGN' && f.detection_outcome !== 'BENIGN') {
        return false;
      }

      if (minPackets > 0 && f.total_packets < minPackets) {
        return false;
      }

      return true;
    });
  }, [flows, searchQuery, selectedProto, selectedOutcome, minPackets]);

  const handleSimulateRefresh = () => {
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
    }, 600);
  };

  const resetFilters = () => {
    setSelectedProto('ALL');
    setSelectedOutcome('ALL');
    setMinPackets(0);
    onSearchChange('');
    setSimulateError(false);
  };

  const exportFlowsCSV = () => {
    const headers = ['Flow ID', 'Source IP', 'Source Port', 'Dest IP', 'Dest Port', 'Protocol', 'Duration', 'Packets', 'Bytes', 'Outcome', 'Related Alert'];
    const rows = filteredFlows.map(f => [
      f.flow_id,
      f.src_ip,
      f.src_port ?? '—',
      f.dst_ip,
      f.dst_port ?? '—',
      f.protocol,
      f.duration.toFixed(4),
      f.total_packets,
      f.total_bytes,
      f.detection_outcome,
      f.related_alert_id ?? '—'
    ]);

    const csvContent = "data:text/csv;charset=utf-8," + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `netra_flows_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    link.remove();
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-xl sm:text-2xl font-heading font-extrabold text-[#F5F5F7] tracking-tight">
            Network Flow Explorer
          </h2>
          <p className="text-xs text-[#A5A5BE] font-mono mt-1">
            Standardized bidirectional flow records extracted from passive packet headers
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleSimulateRefresh}
            className="flex items-center gap-2 px-3 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] text-xs font-mono transition-all cursor-pointer"
            title="Poll ring buffer"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Refresh</span>
          </button>

          <button
            onClick={exportFlowsCSV}
            className="flex items-center gap-2 px-3.5 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#F5F5F7] text-xs font-mono font-medium transition-all cursor-pointer"
          >
            <Download className="w-4 h-4 text-[#39D7FF]" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Metadata Transparency Notice */}
      <div className="p-3.5 rounded-xl bg-[#10103D]/60 border border-[#242452] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono">
        <div className="flex items-center gap-2 text-[#39D7FF]">
          <Info className="w-4 h-4 shrink-0" />
          <span>
            Zero-Payload Storage Architecture • Zero Application Bytes Retained
          </span>
        </div>
        <div className="flex items-center gap-2 text-[#A5A5BE] text-[11px]">
          <span>Showing {filteredFlows.length} flows</span>
          <span>•</span>
          <button
            onClick={() => setSimulateError(!simulateError)}
            className="text-[10px] text-[#A5A5BE] hover:text-[#F7B84B] underline cursor-pointer"
          >
            {simulateError ? 'Clear simulated error state' : 'Test error state'}
          </button>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="p-4 rounded-2xl bg-[#10103D]/80 border border-[#242452] shadow-xl space-y-4">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs font-mono">
          {/* Search Box */}
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#A5A5BE]" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search by flow ID, IP..."
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl pl-9 pr-3 py-2 text-xs font-mono text-[#F5F5F7] placeholder-[#A5A5BE]/60 focus:outline-none focus:border-[#39D7FF]"
            />
          </div>

          {/* Protocol Filter */}
          <div>
            <select
              value={selectedProto}
              onChange={(e) => setSelectedProto(e.target.value)}
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF]"
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>

          {/* Outcome Filter */}
          <div>
            <select
              value={selectedOutcome}
              onChange={(e) => setSelectedOutcome(e.target.value)}
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF]"
            >
              <option value="ALL">All Outcomes</option>
              <option value="THREAT">Threat Alert Triggered</option>
              <option value="BENIGN">Benign / Clean</option>
            </select>
          </div>

          {/* Min Packets Filter & Reset */}
          <div className="flex items-center gap-2">
            <select
              value={minPackets}
              onChange={(e) => setMinPackets(Number(e.target.value))}
              className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF]"
            >
              <option value="0">Min Packets: Any</option>
              <option value="5">&gt;= 5 Packets</option>
              <option value="20">&gt;= 20 Packets</option>
              <option value="500">&gt;= 500 Packets</option>
            </select>

            {(selectedProto !== 'ALL' || selectedOutcome !== 'ALL' || minPackets > 0 || searchQuery) && (
              <button
                onClick={resetFilters}
                className="p-2 rounded-xl bg-[#07072B] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all cursor-pointer"
                title="Reset filters"
              >
                <RotateCcw className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>
      </div>

      {/* Simulated Error State */}
      {simulateError ? (
        <div className="p-8 rounded-2xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 text-center font-mono space-y-3">
          <ShieldAlert className="w-10 h-10 text-[#FF4D5A] mx-auto" />
          <h4 className="text-base font-bold text-[#F5F5F7]">Network Ingestion Failure (Simulated)</h4>
          <p className="text-xs text-[#A5A5BE] max-w-md mx-auto">
            Unable to poll ring buffer descriptor table on eth0. Interface read permissions or ring buffer socket timeout.
          </p>
          <button
            onClick={() => setSimulateError(false)}
            className="px-4 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-xs text-[#39D7FF] cursor-pointer"
          >
            Recover & Reset Buffer
          </button>
        </div>
      ) : isLoading ? (
        /* Loading State */
        <div className="p-16 rounded-2xl bg-[#10103D]/60 border border-[#242452] text-center font-mono space-y-3">
          <div className="w-8 h-8 rounded-full border-2 border-[#39D7FF] border-t-transparent animate-spin mx-auto" />
          <p className="text-xs text-[#A5A5BE]">Re-indexing flow ring buffer...</p>
        </div>
      ) : (
        /* Flow Table */
        <div className="rounded-2xl bg-[#10103D]/60 border border-[#242452] overflow-hidden shadow-2xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-[#242452] bg-[#07072B]/60 text-[#A5A5BE] text-[11px]">
                  <th className="py-3 px-4">Flow ID</th>
                  <th className="py-3 px-4">Source Host</th>
                  <th className="py-3 px-4">Destination Host</th>
                  <th className="py-3 px-4">Proto</th>
                  <th className="py-3 px-4">Duration</th>
                  <th className="py-3 px-4">Packets</th>
                  <th className="py-3 px-4">Bytes</th>
                  <th className="py-3 px-4">Rate (pps)</th>
                  <th className="py-3 px-4">Detection Outcome</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#242452]/50">
                {filteredFlows.length > 0 ? (
                  filteredFlows.map((flow) => {
                    const isThreat = flow.detection_outcome !== 'BENIGN';

                    return (
                      <tr
                        key={flow.flow_id}
                        onClick={() => onSelectFlow(flow)}
                        className="hover:bg-[#15154A]/50 transition-colors cursor-pointer group"
                      >
                        <td className="py-3.5 px-4 text-[#39D7FF] font-semibold whitespace-nowrap">
                          {flow.flow_id.slice(0, 16)}...
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="text-[#F5F5F7] font-semibold">{flow.src_ip}</span>
                          <span className="text-[#A5A5BE] ml-1">:{flow.src_port ?? '—'}</span>
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          <span className="text-[#F5F5F7] font-semibold">{flow.dst_ip}</span>
                          <span className="text-[#A5A5BE] ml-1">:{flow.dst_port ?? '—'}</span>
                        </td>

                        <td className="py-3.5 px-4 font-bold text-[#A8F500]">
                          {flow.protocol}
                        </td>

                        <td className="py-3.5 px-4 text-[#A5A5BE] whitespace-nowrap">
                          {flow.duration.toFixed(3)}s
                        </td>

                        <td className="py-3.5 px-4 text-[#F5F5F7] whitespace-nowrap">
                          {flow.total_packets.toLocaleString()}
                        </td>

                        <td className="py-3.5 px-4 text-[#A5A5BE] whitespace-nowrap">
                          {(flow.total_bytes / 1024).toFixed(1)} KB
                        </td>

                        <td className="py-3.5 px-4 text-[#39D7FF] whitespace-nowrap">
                          {flow.packets_per_second.toFixed(1)}
                        </td>

                        <td className="py-3.5 px-4 whitespace-nowrap">
                          {isThreat ? (
                            <span className="text-[10px] px-2 py-0.5 rounded border font-bold bg-[#FF4D5A]/15 text-[#FF4D5A] border-[#FF4D5A]/30">
                              {flow.detection_outcome}
                            </span>
                          ) : (
                            <span className="text-[10px] px-2 py-0.5 rounded border font-semibold bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/30">
                              Normal
                            </span>
                          )}
                        </td>

                        <td className="py-3.5 px-4 text-right whitespace-nowrap">
                          <div className="flex items-center justify-end gap-2">
                            {flow.related_alert_id && onNavigateToAlert && (
                              <button
                                onClick={(e) => {
                                  e.stopPropagation();
                                  onNavigateToAlert(flow.related_alert_id!);
                                }}
                                className="text-[10px] px-2 py-1 rounded bg-[#FF4D5A]/15 hover:bg-[#FF4D5A]/25 text-[#FF4D5A] border border-[#FF4D5A]/30 font-bold transition-all cursor-pointer"
                                title="View Triggered Alert"
                              >
                                Alert
                              </button>
                            )}

                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                onSelectFlow(flow);
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
                ) : flows.length === 0 ? (
                  /* Empty Database State */
                  <tr>
                    <td colSpan={10} className="py-16 text-center text-[#A5A5BE] font-mono">
                      <Network className="w-8 h-8 text-[#39D7FF] mx-auto mb-2 opacity-50" />
                      <p className="text-sm font-semibold text-[#F5F5F7]">No network flows observed yet</p>
                      <p className="text-xs text-[#A5A5BE] mt-1 max-w-md mx-auto">
                        Passive monitoring will assemble and display real flows as network packets are captured on the host adapter.
                      </p>
                    </td>
                  </tr>
                ) : (
                  /* Filtered Empty State */
                  <tr>
                    <td colSpan={10} className="py-12 text-center text-[#A5A5BE] font-mono">
                      <Network className="w-8 h-8 text-[#39D7FF] mx-auto mb-2 opacity-60" />
                      <p className="text-sm font-semibold text-[#F5F5F7]">No matching network flows found</p>
                      <p className="text-xs text-[#A5A5BE] mt-1">Adjust search parameters or reset protocol filters</p>
                      <button
                        onClick={resetFilters}
                        className="mt-3 px-4 py-1.5 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-xs text-[#39D7FF] cursor-pointer"
                      >
                        Reset Filters
                      </button>
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
