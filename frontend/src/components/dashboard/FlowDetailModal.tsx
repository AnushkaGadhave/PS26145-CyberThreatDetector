import React from 'react';
import {
  X,
  Network,
  ExternalLink,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import type { NetworkFlow } from '../../types/telemetry';

interface FlowDetailModalProps {
  flow: NetworkFlow | null;
  onClose: () => void;
  onNavigateToAlert?: (alertId: string) => void;
}

export const FlowDetailModal: React.FC<FlowDetailModalProps> = ({
  flow,
  onClose,
  onNavigateToAlert
}) => {
  if (!flow) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm animate-in fade-in">
      <div
        className="w-full max-w-3xl bg-[#07072B] border border-[#242452] rounded-2xl p-6 sm:p-8 max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col justify-between"
        role="dialog"
        aria-modal="true"
      >
        <div>
          {/* Header */}
          <div className="flex items-center justify-between pb-4 border-b border-[#242452]">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-[#10103D] border border-[#242452] flex items-center justify-center">
                <Network className="w-5 h-5 text-[#39D7FF]" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <h3 className="font-heading font-extrabold text-lg text-[#F5F5F7]">
                    Flow Inspection Record
                  </h3>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#242452] text-[#A8F500]">
                    {flow.protocol}
                  </span>
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                    flow.detection_outcome !== 'BENIGN'
                      ? 'bg-[#FF4D5A]/15 text-[#FF4D5A] border-[#FF4D5A]/40'
                      : 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/40'
                  }`}>
                    {flow.detection_outcome}
                  </span>
                </div>
                <span className="text-xs font-mono text-[#A5A5BE]">
                  {flow.flow_id}
                </span>
              </div>
            </div>

            <button
              onClick={onClose}
              className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all cursor-pointer"
              aria-label="Close flow modal"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* 5-Tuple & Temporal Summary */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 my-5">
            <div className="p-4 rounded-xl bg-[#10103D]/60 border border-[#242452] space-y-2 text-xs font-mono">
              <span className="text-[#39D7FF] font-bold block text-[11px] uppercase tracking-wider">
                Network 5-Tuple
              </span>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">Source:</span>
                <span className="text-[#F5F5F7] font-semibold">
                  {flow.src_ip} {flow.src_port !== null ? `:${flow.src_port}` : ''}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">Destination:</span>
                <span className="text-[#F5F5F7] font-semibold">
                  {flow.dst_ip} {flow.dst_port !== null ? `:${flow.dst_port}` : ''}
                </span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">Protocol:</span>
                <span className="text-[#39D7FF]">{flow.protocol}</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[#A5A5BE]">Context:</span>
                <span className="text-[#A8F500]">{flow.traffic_context}</span>
              </div>
            </div>

            <div className="p-4 rounded-xl bg-[#10103D]/60 border border-[#242452] space-y-2 text-xs font-mono">
              <span className="text-[#39D7FF] font-bold block text-[11px] uppercase tracking-wider">
                Timing & Rates
              </span>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">Active Duration:</span>
                <span className="text-[#F5F5F7] font-semibold">{flow.duration.toFixed(4)} sec</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">Packet Velocity:</span>
                <span className="text-[#F5F5F7]">{flow.packets_per_second.toFixed(2)} pps</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">Bandwidth:</span>
                <span className="text-[#F5F5F7]">{(flow.bytes_per_second / 1024).toFixed(2)} KB/s</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[#A5A5BE]">Mean IAT:</span>
                <span className="text-[#F5F5F7]">{(flow.iat_mean * 1000).toFixed(2)} ms</span>
              </div>
            </div>
          </div>

          {/* Volumetric Breakdown */}
          <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 mb-5">
            <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider block mb-3">
              Volumetric & Ratio Telemetry
            </span>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs font-mono">
              <div className="p-2.5 rounded-lg bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] text-[#A5A5BE] block">Total Packets</span>
                <span className="text-sm font-bold text-[#F5F5F7] mt-1 block">{flow.total_packets.toLocaleString()}</span>
                <span className="text-[10px] text-[#A5A5BE]">Fwd: {flow.forward_packets} | Bwd: {flow.backward_packets}</span>
              </div>

              <div className="p-2.5 rounded-lg bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] text-[#A5A5BE] block">Total Bytes</span>
                <span className="text-sm font-bold text-[#F5F5F7] mt-1 block">{flow.total_bytes.toLocaleString()} B</span>
                <span className="text-[10px] text-[#A5A5BE]">Fwd: {flow.forward_bytes} | Bwd: {flow.backward_bytes}</span>
              </div>

              <div className="p-2.5 rounded-lg bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] text-[#A5A5BE] block">Fwd Packet Ratio</span>
                <span className="text-sm font-bold text-[#39D7FF] mt-1 block">{(flow.forward_packet_ratio * 100).toFixed(1)}%</span>
                <span className="text-[10px] text-[#A5A5BE]">Bwd: {(flow.backward_packet_ratio * 100).toFixed(1)}%</span>
              </div>

              <div className="p-2.5 rounded-lg bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] text-[#A5A5BE] block">Bytes Per Packet</span>
                <span className="text-sm font-bold text-[#A8F500] mt-1 block">{flow.bytes_per_packet.toFixed(1)} B</span>
                <span className="text-[10px] text-[#A5A5BE]">{flow.packets_per_byte.toFixed(4)} pkt/B</span>
              </div>
            </div>
          </div>

          {/* TCP Flags & IAT Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-5">
            {/* TCP Flags */}
            <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 text-xs font-mono">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider block mb-3">
                TCP Control Flags
              </span>
              <div className="grid grid-cols-3 gap-2 text-center">
                <div className={`p-2 rounded border ${flow.syn_count > 0 ? 'bg-[#FF4D5A]/15 border-[#FF4D5A]/40 text-[#FF4D5A]' : 'bg-[#07072B] border-[#242452] text-[#A5A5BE]'}`}>
                  <span className="text-[10px] block font-bold">SYN</span>
                  <span className="text-sm font-bold mt-0.5 block">{flow.syn_count}</span>
                </div>
                <div className={`p-2 rounded border ${flow.ack_count > 0 ? 'bg-[#39D7FF]/15 border-[#39D7FF]/40 text-[#39D7FF]' : 'bg-[#07072B] border-[#242452] text-[#A5A5BE]'}`}>
                  <span className="text-[10px] block font-bold">ACK</span>
                  <span className="text-sm font-bold mt-0.5 block">{flow.ack_count}</span>
                </div>
                <div className={`p-2 rounded border ${flow.psh_count > 0 ? 'bg-[#F7B84B]/15 border-[#F7B84B]/40 text-[#F7B84B]' : 'bg-[#07072B] border-[#242452] text-[#A5A5BE]'}`}>
                  <span className="text-[10px] block font-bold">PSH</span>
                  <span className="text-sm font-bold mt-0.5 block">{flow.psh_count}</span>
                </div>
                <div className={`p-2 rounded border ${flow.fin_count > 0 ? 'bg-[#A8F500]/15 border-[#A8F500]/40 text-[#A8F500]' : 'bg-[#07072B] border-[#242452] text-[#A5A5BE]'}`}>
                  <span className="text-[10px] block font-bold">FIN</span>
                  <span className="text-sm font-bold mt-0.5 block">{flow.fin_count}</span>
                </div>
                <div className={`p-2 rounded border ${flow.rst_count > 0 ? 'bg-[#FF4D5A]/15 border-[#FF4D5A]/40 text-[#FF4D5A]' : 'bg-[#07072B] border-[#242452] text-[#A5A5BE]'}`}>
                  <span className="text-[10px] block font-bold">RST</span>
                  <span className="text-sm font-bold mt-0.5 block">{flow.rst_count}</span>
                </div>
                <div className={`p-2 rounded border ${flow.urg_count > 0 ? 'bg-[#FF8A3D]/15 border-[#FF8A3D]/40 text-[#FF8A3D]' : 'bg-[#07072B] border-[#242452] text-[#A5A5BE]'}`}>
                  <span className="text-[10px] block font-bold">URG</span>
                  <span className="text-sm font-bold mt-0.5 block">{flow.urg_count}</span>
                </div>
              </div>
            </div>

            {/* IAT Stats */}
            <div className="rounded-xl bg-[#10103D]/60 border border-[#242452] p-4 text-xs font-mono space-y-2">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider block mb-3">
                Inter-Arrival Times (IAT)
              </span>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">IAT Mean:</span>
                <span className="text-[#F5F5F7] font-semibold">{(flow.iat_mean * 1000).toFixed(3)} ms</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">IAT Std Dev:</span>
                <span className="text-[#F5F5F7]">{(flow.iat_std * 1000).toFixed(3)} ms</span>
              </div>
              <div className="flex justify-between py-1 border-b border-[#242452]/40">
                <span className="text-[#A5A5BE]">IAT Min:</span>
                <span className="text-[#F5F5F7]">{(flow.iat_min * 1000).toFixed(3)} ms</span>
              </div>
              <div className="flex justify-between py-1">
                <span className="text-[#A5A5BE]">IAT Max:</span>
                <span className="text-[#F5F5F7]">{(flow.iat_max * 1000).toFixed(3)} ms</span>
              </div>
            </div>
          </div>

          {/* Linked Alert Section */}
          {flow.related_alert_id ? (
            <div className="p-4 rounded-xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono">
              <div className="flex items-center gap-2 text-[#FF4D5A]">
                <ShieldAlert className="w-5 h-5 shrink-0" />
                <div>
                  <span className="font-bold block">Threat Alert Generated</span>
                  <span className="text-[11px] text-[#A5A5BE]">ID: {flow.related_alert_id}</span>
                </div>
              </div>

              {onNavigateToAlert && (
                <button
                  onClick={() => onNavigateToAlert(flow.related_alert_id!)}
                  className="px-4 py-2 rounded-lg bg-[#FF4D5A] hover:bg-[#FF6470] text-[#07072B] font-bold text-xs flex items-center gap-1.5 transition-all cursor-pointer"
                >
                  <span>Inspect Related Alert</span>
                  <ExternalLink className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          ) : (
            <div className="p-3.5 rounded-xl bg-[#7DDB52]/10 border border-[#7DDB52]/30 flex items-center gap-2 text-xs font-mono text-[#7DDB52]">
              <ShieldCheck className="w-4 h-4 shrink-0" />
              <span>Normal Traffic Baseline — Flow features within safe statistical boundaries.</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="mt-6 pt-4 border-t border-[#242452] flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#F5F5F7] text-xs font-mono font-semibold transition-all cursor-pointer"
          >
            Close Flow Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
