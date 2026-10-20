import React, { useState, useEffect, useRef } from 'react';
import {
  Play,
  Square,
  Radio,
  Server,
  Activity,
  ArrowUpRight,
  RefreshCw,
  CheckCircle2,
  AlertCircle,
  ShieldAlert
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import {
  api,
  type CaptureStatus,
  type CaptureInterface,
  type LiveStreamEventItem
} from '../../services/api';

interface LiveMonitorPageProps {
  onSelectAlertById?: (alertId: string) => void;
  onRefreshParent?: () => void;
}

export const LiveMonitorPage: React.FC<LiveMonitorPageProps> = ({
  onSelectAlertById,
  onRefreshParent
}) => {
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';
  const [interfaces, setInterfaces] = useState<CaptureInterface[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('');
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);
  const [events, setEvents] = useState<LiveStreamEventItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [isStopping, setIsStopping] = useState<boolean>(false);

  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Initial load: interfaces and current status
  useEffect(() => {
    let mounted = true;

    async function loadInitial() {
      setIsLoading(true);
      setActionError(null);
      try {
        const [ifaceList, statusData] = await Promise.all([
          api.getCaptureInterfaces(),
          api.getCaptureStatus()
        ]);

        if (mounted) {
          setInterfaces(ifaceList);
          setCaptureStatus(statusData);

          // Select current running interface, or first active, or first available
          if (statusData.interface) {
            setSelectedInterface(statusData.interface);
          } else {
            const activeOne = ifaceList.find(i => i.is_active && i.ip);
            if (activeOne) {
              setSelectedInterface(activeOne.name);
            } else if (ifaceList.length > 0) {
              setSelectedInterface(ifaceList[0].name);
            }
          }
        }
      } catch (err: any) {
        if (mounted) {
          setActionError(err.message || 'Failed to connect to backend capture service.');
        }
      } finally {
        if (mounted) {
          setIsLoading(false);
        }
      }
    }

    loadInitial();

    return () => {
      mounted = false;
    };
  }, []);

  // Polling loop for status and live events
  useEffect(() => {
    let isPolling = true;

    async function poll() {
      try {
        const [statusData, recentEvents] = await Promise.all([
          api.getCaptureStatus(),
          api.getRecentLiveEvents(30)
        ]);

        if (isPolling) {
          setCaptureStatus(statusData);
          setEvents(recentEvents);
        }
      } catch {
        // Suppress transient poll error
      }
    }

    // Run poll immediately then set interval
    poll();
    pollTimerRef.current = setInterval(poll, 1500);

    return () => {
      isPolling = false;
      if (pollTimerRef.current) {
        clearInterval(pollTimerRef.current);
      }
    };
  }, []);

  const handleStart = async () => {
    setIsStarting(true);
    setActionError(null);
    setActionSuccess(null);

    try {
      const res = await api.startCapture(selectedInterface || undefined);
      if (res.success) {
        setActionSuccess(res.message);
        // Refresh status immediately
        const newStatus = await api.getCaptureStatus();
        setCaptureStatus(newStatus);
        if (onRefreshParent) onRefreshParent();
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to start capture.');
    } finally {
      setIsStarting(false);
    }
  };

  const handleStop = async () => {
    setIsStopping(true);
    setActionError(null);
    setActionSuccess(null);

    try {
      const res = await api.stopCapture();
      if (res.success) {
        setActionSuccess(res.message);
        // Refresh status immediately
        const newStatus = await api.getCaptureStatus();
        setCaptureStatus(newStatus);
        if (onRefreshParent) onRefreshParent();
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to stop capture.');
    } finally {
      setIsStopping(false);
    }
  };

  const isCapturing = captureStatus?.state === 'ACTIVE';

  const getStatusBadge = () => {
    if (captureStatus?.state === 'ACTIVE') {
      return (
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#7DDB52]/15 border border-[#7DDB52]/40 text-[#7DDB52] font-mono text-xs font-bold">
          <span className="w-2.5 h-2.5 rounded-full bg-[#7DDB52] animate-pulse" />
          <span>ACTIVE PASSIVE CAPTURE</span>
        </div>
      );
    } else if (captureStatus?.state === 'ERROR') {
      return (
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] font-mono text-xs font-bold">
          <span className="w-2.5 h-2.5 rounded-full bg-[#FF4D5A]" />
          <span>CAPTURE ERROR</span>
        </div>
      );
    } else {
      return (
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#A5A5BE]/15 border border-[#A5A5BE]/40 text-[#A5A5BE] font-mono text-xs font-bold">
          <span className="w-2.5 h-2.5 rounded-full bg-[#A5A5BE]" />
          <span>MONITORING STOPPED</span>
        </div>
      );
    }
  };

  return (
    <div className="space-y-6 pb-12 animate-in fade-in duration-300">
      {/* Top Banner Notice */}
      <div className={`p-4 rounded-2xl border flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs font-mono shadow-xl ${
        isCapturing
          ? 'bg-[#10103D] border-[#7DDB52]/40 text-[#7DDB52]'
          : 'bg-[#10103D] border-[#242452] text-[#A5A5BE]'
      }`}>
        <div className="flex items-center gap-2.5">
          {isCapturing ? (
            <Radio className="w-5 h-5 text-[#7DDB52] animate-pulse shrink-0" />
          ) : (
            <Server className="w-5 h-5 text-[#39D7FF] shrink-0" />
          )}
          <div>
            <span className="font-bold block text-[#F5F5F7]">
              {isCapturing
                ? `PASSIVE CAPTURE ONLINE — SNIFFING ON ${captureStatus?.interface || selectedInterface}`
                : 'PASSIVE NETWORK SENSOR READY — SELECT INTERFACE & START MONITORING'}
            </span>
            <span className="text-[11px] text-[#A5A5BE] font-sans">
              Real packet ingestion via Npcap/Scapy. Zero payload retained. Flows analyzed by trained ML detectors.
            </span>
          </div>
        </div>

        <div className="shrink-0">{getStatusBadge()}</div>
      </div>

      {/* Action alerts if any */}
      {actionError && (
        <div className="p-3.5 rounded-xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 text-xs font-mono text-[#FF4D5A] flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{actionError}</span>
        </div>
      )}
      {actionSuccess && (
        <div className="p-3.5 rounded-xl bg-[#7DDB52]/10 border border-[#7DDB52]/30 text-xs font-mono text-[#7DDB52] flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{actionSuccess}</span>
        </div>
      )}

      {/* Main Controls & Live Rate Dashboard */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Controls Card */}
        <div className="rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider flex items-center gap-2">
                <Radio className="w-4 h-4 text-[#A8F500]" />
                Passive Sensor Controls
              </span>
              <span className="text-[11px] font-mono text-[#39D7FF]">READ-ONLY INGRESS</span>
            </div>

            {/* Interface Selector Dropdown */}
            <div className="mb-4">
              <label className="block text-[11px] font-mono text-[#A5A5BE] mb-1.5 uppercase">
                Target Capture Interface
              </label>
              <select
                value={selectedInterface}
                onChange={(e) => setSelectedInterface(e.target.value)}
                disabled={isCapturing || isLoading || !isAdmin}
                className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF] disabled:opacity-60 disabled:cursor-not-allowed"
              >
                {interfaces.map((iface) => (
                  <option key={iface.name} value={iface.name}>
                    {iface.name} {iface.ip ? `(${iface.ip})` : '(No IP)'} {iface.is_active ? '• Active' : ''}
                  </option>
                ))}
              </select>
            </div>

            {/* Non-admin read-only notification */}
            {!isAdmin && (
              <div className="mb-4 p-3 rounded-xl bg-[#39D7FF]/10 border border-[#39D7FF]/30 text-xs font-mono text-[#39D7FF] flex items-start gap-2.5">
                <ShieldAlert className="w-4 h-4 shrink-0 mt-0.5 text-[#39D7FF]" />
                <div className="leading-tight">
                  <span className="font-bold block text-[#F5F5F7] mb-0.5">READ-ONLY ANALYST ACCESS</span>
                  <span className="text-[11px] text-[#A5A5BE]">Packet sniffer controls require Administrator privileges. Live telemetry remains accessible in passive read-only mode.</span>
                </div>
              </div>
            )}

            <p className="text-xs text-[#A5A5BE] font-sans mb-5 leading-relaxed">
              Launches a dedicated passive background sniffer worker thread. Halting capture flushes all active flows into the ML detection pipeline and PostgreSQL.
            </p>

            <div className="grid grid-cols-2 gap-3 mb-4">
              {isCapturing ? (
                <button
                  onClick={handleStop}
                  disabled={isStopping || !isAdmin}
                  title={!isAdmin ? "Administrator role required to stop capture" : undefined}
                  className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#FF4D5A]/20 hover:bg-[#FF4D5A]/30 border border-[#FF4D5A]/50 text-[#FF4D5A] text-xs font-mono font-bold transition-all cursor-pointer shadow-md shadow-[#FF4D5A]/10 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Square className="w-4 h-4" />
                  <span>{isStopping ? 'Stopping...' : 'Stop Monitoring'}</span>
                </button>
              ) : (
                <button
                  onClick={handleStart}
                  disabled={isStarting || isLoading || !isAdmin}
                  title={!isAdmin ? "Administrator role required to start capture" : undefined}
                  className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#A8F500] hover:bg-[#B7FF19] text-[#07072B] text-xs font-mono font-bold transition-all cursor-pointer shadow-md shadow-[#A8F500]/20 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>{isStarting ? 'Starting...' : 'Start Monitoring'}</span>
                </button>
              )}

              <button
                onClick={async () => {
                  try {
                    const st = await api.getCaptureStatus();
                    setCaptureStatus(st);
                  } catch {}
                }}
                className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#39D7FF] text-xs font-mono font-bold transition-all cursor-pointer"
              >
                <RefreshCw className="w-4 h-4" />
                <span>Refresh Status</span>
              </button>
            </div>
          </div>

          <div className="pt-4 border-t border-[#242452] flex items-center justify-between text-xs font-mono">
            <span className="text-[#A5A5BE]">
              Interface: <strong className="text-[#F5F5F7]">{captureStatus?.interface || selectedInterface || 'Auto'}</strong>
            </span>
            <span className={isCapturing ? 'text-[#7DDB52]' : 'text-[#A5A5BE]'}>
              {isCapturing ? 'Sniffing Active' : 'Standby'}
            </span>
          </div>
        </div>

        {/* Live Metrics: Rate & Counters (2 Cols) */}
        <div className="lg:col-span-2 rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#39D7FF]" />
                Live Ingress Metrics & Volume
              </span>
              <span className="text-xs font-mono text-[#A8F500]">
                {isCapturing ? 'LIVE HARDWARE COUNTERS' : 'IDLE'}
              </span>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-5">
              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Packets Captured</span>
                <span className="text-2xl font-heading font-extrabold text-[#F5F5F7] mt-1 block">
                  {(captureStatus?.packets_captured ?? 0).toLocaleString()}
                </span>
                <span className="text-[10px] font-mono text-[#7DDB52]">Observed Packets</span>
              </div>

              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Flows Created</span>
                <span className="text-2xl font-heading font-extrabold text-[#39D7FF] mt-1 block">
                  {(captureStatus?.flows_created ?? 0).toLocaleString()}
                </span>
                <span className="text-[10px] font-mono text-[#39D7FF]">Aggregated</span>
              </div>

              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Threats Detected</span>
                <span className="text-2xl font-heading font-extrabold text-[#FF4D5A] mt-1 block">
                  {captureStatus?.threats_detected ?? 0}
                </span>
                <span className="text-[10px] font-mono text-[#FF4D5A]">Alerts Generated</span>
              </div>

              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Packet Rate</span>
                <span className="text-2xl font-heading font-extrabold text-[#A8F500] mt-1 block">
                  {(captureStatus?.current_pps ?? 0).toLocaleString()}
                </span>
                <span className="text-[10px] font-mono text-[#A5A5BE]">Packets / sec</span>
              </div>
            </div>

            {/* Visual Bar Meters */}
            <div className="space-y-3">
              <div>
                <div className="flex justify-between text-xs font-mono text-[#A5A5BE] mb-1">
                  <span>Packet Ingress Velocity ({captureStatus?.current_pps ?? 0} pps)</span>
                  <span className="text-[#39D7FF]">
                    {captureStatus?.last_packet_time
                      ? `Last observed: ${new Date(captureStatus.last_packet_time * 1000).toLocaleTimeString()}`
                      : 'Awaiting traffic'}
                  </span>
                </div>
                <div className="w-full h-2 rounded-full bg-[#07072B] border border-[#242452] overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-[#39D7FF] to-[#A8F500] transition-all duration-300 rounded-full"
                    style={{ width: `${Math.min(100, ((captureStatus?.current_pps ?? 0) / 1000) * 100)}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex justify-between text-xs font-mono text-[#A5A5BE] mb-1">
                  <span>Estimated Bandwidth ({captureStatus?.current_kbps ?? 0} KB/s)</span>
                  <span className="text-[#A8F500]">Headers Only</span>
                </div>
                <div className="w-full h-2 rounded-full bg-[#07072B] border border-[#242452] overflow-hidden">
                  <div
                    className="h-full bg-gradient-to-r from-[#7DDB52] to-[#FF8A3D] transition-all duration-300 rounded-full"
                    style={{ width: `${Math.min(100, ((captureStatus?.current_kbps ?? 0) / 500) * 100)}%` }}
                  />
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#242452] flex items-center justify-between text-xs font-mono text-[#A5A5BE]">
            <span>Zero Payload Stored • Header Metadata & Statistical Features Only</span>
            <span className="text-[#7DDB52]">
              Drops: {captureStatus?.packets_dropped ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* Split: Live Flow Stream Feed + Capture Hardware Information */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Feed (2 Cols) */}
        <div className="lg:col-span-2 rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h4 className="text-sm font-heading font-semibold text-[#F5F5F7] flex items-center gap-2">
                <span>Recent Live Ingress Events</span>
                {isCapturing && (
                  <span className="w-2 h-2 rounded-full bg-[#7DDB52] animate-ping" />
                )}
              </h4>
              <p className="text-[11px] text-[#A5A5BE]">
                Real packets ingested by Scapy, parsed by FlowBuilder, and evaluated by ML models
              </p>
            </div>

            <span className="text-xs font-mono text-[#A5A5BE]">
              Showing {events.length} latest live observations
            </span>
          </div>

          {events.length > 0 ? (
            <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
              {events.map((evt) => {
                const isThreat = evt.threat_outcome !== 'BENIGN';
                const timeFormatted = new Date(evt.timestamp * 1000).toLocaleTimeString();

                return (
                  <div
                    key={evt.id}
                    className={`p-3 rounded-xl border transition-all text-xs font-mono flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                      isThreat
                        ? 'bg-[#FF4D5A]/10 border-[#FF4D5A]/30 hover:bg-[#FF4D5A]/15'
                        : 'bg-[#07072B] border-[#242452] hover:bg-[#15154A]/30'
                    }`}
                  >
                    <div className="flex items-center gap-3">
                      <span className="text-[#A5A5BE] text-[11px] shrink-0">{timeFormatted}</span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#10103D] text-[#39D7FF] font-bold">
                        {evt.protocol}
                      </span>
                      <div className="flex items-center gap-1.5 text-xs">
                        <span className="text-[#F5F5F7] font-semibold">{evt.src_ip}</span>
                        <span className="text-[#A5A5BE] opacity-60">→</span>
                        <span className="text-[#A5A5BE]">{evt.dst_ip}:{evt.dst_port ?? '—'}</span>
                      </div>
                    </div>

                    <div className="flex items-center gap-3 w-full sm:w-auto justify-between sm:justify-end">
                      <span className="text-[11px] text-[#A5A5BE]">
                        {evt.packets} pkts • {evt.bytes} B
                      </span>

                      <span
                        className={`text-[10px] px-2 py-0.5 rounded border font-bold ${
                          isThreat
                            ? 'bg-[#FF4D5A]/20 text-[#FF4D5A] border-[#FF4D5A]/40 animate-pulse'
                            : 'bg-[#7DDB52]/15 text-[#7DDB52] border-[#7DDB52]/30'
                        }`}
                      >
                        {evt.threat_outcome}
                      </span>

                      {evt.alert_id && onSelectAlertById && (
                        <button
                          onClick={() => onSelectAlertById(evt.alert_id!)}
                          className="text-[#A8F500] hover:underline text-[11px] inline-flex items-center gap-1 cursor-pointer"
                          title="Inspect Triggered Alert"
                        >
                          <ArrowUpRight className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="py-16 text-center text-[#A5A5BE] font-mono border border-dashed border-[#242452] rounded-xl">
              <Radio className="w-8 h-8 text-[#39D7FF] mx-auto mb-2 opacity-50" />
              <p className="text-sm font-semibold text-[#F5F5F7]">
                {isCapturing
                  ? 'Passive capture active — waiting for network packets...'
                  : 'No network flows observed yet'}
              </p>
              <p className="text-xs text-[#A5A5BE] mt-1 max-w-md mx-auto">
                {isCapturing
                  ? `Listening on ${captureStatus?.interface || selectedInterface}. Transmit traffic on this interface to see live flows and detection results.`
                  : 'Click "Start Monitoring" above to start passive sniffing on the selected network adapter.'}
              </p>
            </div>
          )}
        </div>

        {/* Capture Hardware & Source Panel (1 Col) */}
        <div className="rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider flex items-center gap-2">
                <Server className="w-4 h-4 text-[#39D7FF]" />
                Sensor Architecture Details
              </span>
              <span className="text-xs font-mono text-[#7DDB52]">NPCAP PASSIVE</span>
            </div>

            <div className="space-y-3 text-xs font-mono">
              <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452] space-y-1">
                <span className="text-[#A5A5BE] text-[10px] uppercase">Selected Adapter</span>
                <div className="flex items-center justify-between text-[#F5F5F7]">
                  <strong className="text-xs truncate max-w-[170px]">
                    {captureStatus?.interface || selectedInterface || 'Auto'}
                  </strong>
                  <span className="text-[#39D7FF] text-[10px]">Promiscuous RX</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452] space-y-1">
                <span className="text-[#A5A5BE] text-[10px] uppercase">Unidirectional Isolation</span>
                <div className="flex items-center justify-between text-[#F5F5F7]">
                  <span className="text-[#A8F500] font-bold">Passive Sniff / No TX</span>
                  <span className="text-[10px] text-[#A5A5BE]">Strict RX Mode</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452] space-y-1">
                <span className="text-[#A5A5BE] text-[10px] uppercase">Data Privacy Guarantee</span>
                <div className="flex items-center justify-between text-[#F5F5F7]">
                  <span className="text-[#7DDB52] font-semibold">Zero Packet Payloads</span>
                  <span className="text-[10px] text-[#A5A5BE]">Metadata Only</span>
                </div>
              </div>

              <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452] space-y-1">
                <span className="text-[#A5A5BE] text-[10px] uppercase">Detection Engine</span>
                <div className="flex items-center justify-between text-[#F5F5F7]">
                  <span>RF • Hybrid PCA/DBSCAN • IF</span>
                  <span className="text-[#39D7FF]">3 Models</span>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-[#242452] text-[11px] font-sans text-[#A5A5BE] leading-relaxed">
            Passive capture operates strictly read-only on network traffic. No active packets are transmitted and no application payloads are stored or inspected.
          </div>
        </div>
      </div>
    </div>
  );
};
