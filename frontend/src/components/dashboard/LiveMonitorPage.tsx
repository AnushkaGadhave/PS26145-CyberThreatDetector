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
  AlertTriangle,
  ShieldAlert,
  Laptop,
  Plus,
  Copy,
  Check,
  WifiOff,
  Download
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import { downloadBlob } from '../../utils/exportUtils';
import {
  api,
  type CaptureStatus,
  type CaptureInterface,
  type LiveStreamEventItem,
  type EnrolledSensor
} from '../../services/api';

interface LiveMonitorPageProps {
  onSelectAlertById?: (alertId: string) => void;
  onRefreshParent?: () => void;
}

type DiagnosticState =
  | 'SENSOR_NOT_INSTALLED'
  | 'SENSOR_OFFLINE'
  | 'PERMISSION_REQUIRED'
  | 'INTERFACE_UNAVAILABLE'
  | 'RUNNING_NO_PACKETS'
  | 'ACTIVE_TELEMETRY'
  | 'BACKEND_CONNECTION_LOST'
  | 'OCCUPIED_BY_ANOTHER_USER';

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
  const [enrolledSensors, setEnrolledSensors] = useState<EnrolledSensor[]>([]);
  const [selectedRemoteSensorId, setSelectedRemoteSensorId] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<'all' | 'local' | 'remote'>('all');
  const [selectedSensorFilter, setSelectedSensorFilter] = useState<string>('');
  const [showEnrollModal, setShowEnrollModal] = useState<boolean>(false);
  const [newSensorId, setNewSensorId] = useState<string>('');
  const [newSensorName, setNewSensorName] = useState<string>('');
  const [enrollResult, setEnrollResult] = useState<{ sensor: EnrolledSensor; api_key: string } | null>(null);
  const [copiedKey, setCopiedKey] = useState<boolean>(false);
  const [copiedCmd, setCopiedCmd] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionSuccess, setActionSuccess] = useState<string | null>(null);
  const [isStarting, setIsStarting] = useState<boolean>(false);
  const [isStopping, setIsStopping] = useState<boolean>(false);
  const [backendConnectionLost, setBackendConnectionLost] = useState<boolean>(false);
  const [isDownloadingPackage, setIsDownloadingPackage] = useState<boolean>(false);

  const eventsTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const sensorTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const isPollingEventsRef = useRef<boolean>(false);
  const isPollingSensorsRef = useRef<boolean>(false);
  const backendConnectionLostRef = useRef<boolean>(false);

  // Synchronize backend connection state ref to prevent stale closures in polling loops
  useEffect(() => {
    backendConnectionLostRef.current = backendConnectionLost;
  }, [backendConnectionLost]);

  // Initial load: interfaces, capture status, and enrolled sensors
  useEffect(() => {
    let mounted = true;

    async function loadInitial() {
      setIsLoading(true);
      setActionError(null);
      try {
        const [ifaceList, statusData, sensorList] = await Promise.all([
          api.getCaptureInterfaces().catch(() => []),
          api.getCaptureStatus(),
          api.getEnrolledSensors().catch(() => [])
        ]);

        if (mounted) {
          setBackendConnectionLost(false);
          backendConnectionLostRef.current = false;
          setInterfaces(ifaceList);
          setCaptureStatus(statusData);
          setEnrolledSensors(sensorList);
          if (sensorList.length > 0) {
            setSelectedRemoteSensorId((prev) => prev || sensorList[0].sensor_id);
          }

          // Select current running interface, or preferred physical wireless/LAN with IP, or first available
          if (statusData.interface) {
            setSelectedInterface(statusData.interface);
          } else {
            const preferred = ifaceList.find(i =>
              i.is_active &&
              (i.ip || (i.ips && i.ips.length > 0)) &&
              (i.is_wireless || (!i.description?.toLowerCase().includes('virtualbox') && !i.name?.toLowerCase().includes('virtualbox') && !i.description?.toLowerCase().includes('host-only')))
            );
            const activeOne = preferred || ifaceList.find(i => i.is_active && (i.ip || (i.ips && i.ips.length > 0)));
            if (activeOne) {
              setSelectedInterface(activeOne.name);
            } else if (ifaceList.length > 0) {
              setSelectedInterface(ifaceList[0].name);
            }
          }
        }
      } catch (err: any) {
        if (mounted) {
          setBackendConnectionLost(true);
          backendConnectionLostRef.current = true;
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

  // Periodic polling loops:
  // - Capture status & Live events: 15s (requirement: 15-30s)
  // - Enrolled sensor list: 30s (requirement: 30s)
  // Pauses automatically when tab is hidden or when backend connection is lost.
  useEffect(() => {
    let isPolling = true;

    async function pollStatusAndEvents() {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      if (backendConnectionLostRef.current) return;
      if (isPollingEventsRef.current) return;
      isPollingEventsRef.current = true;

      try {
        const [statusData, localEvents, remoteEvents] = await Promise.all([
          api.getCaptureStatus(),
          api.getRecentLiveEvents(30).catch(() => []),
          api.getRemoteSensorEvents(undefined, 30).catch(() => [])
        ]);

        if (isPolling) {
          setBackendConnectionLost(false);
          backendConnectionLostRef.current = false;
          if (statusData) setCaptureStatus(statusData);

          const taggedLocal = (localEvents || []).map(e => ({
            ...e,
            source: 'LOCAL RX'
          }));

          const taggedRemote = (remoteEvents || []).map(e => ({
            ...e,
            source: e.source || (e.sensor_id ? `SENSOR: ${e.sensor_id}` : 'REMOTE')
          }));

          const merged = [...taggedLocal, ...taggedRemote].sort(
            (a, b) => (b.timestamp || 0) - (a.timestamp || 0)
          );
          setEvents(merged);
        }
      } catch {
        if (isPolling) {
          setBackendConnectionLost(true);
          backendConnectionLostRef.current = true;
        }
      } finally {
        isPollingEventsRef.current = false;
      }
    }

    async function pollSensors() {
      if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return;
      if (backendConnectionLostRef.current) return;
      if (isPollingSensorsRef.current) return;
      isPollingSensorsRef.current = true;

      try {
        const sensorList = await api.getEnrolledSensors().catch(() => []);
        if (isPolling && sensorList) {
          setBackendConnectionLost(false);
          backendConnectionLostRef.current = false;
          setEnrolledSensors(sensorList);
        }
      } catch {
        if (isPolling) {
          setBackendConnectionLost(true);
          backendConnectionLostRef.current = true;
        }
      } finally {
        isPollingSensorsRef.current = false;
      }
    }

    // Run initial queries after mount
    pollStatusAndEvents();
    pollSensors();

    // 15 seconds for capture status and live telemetry
    eventsTimerRef.current = setInterval(pollStatusAndEvents, 15000);
    // 30 seconds for sensor fleet status
    sensorTimerRef.current = setInterval(pollSensors, 30000);

    // Refresh immediately when returning to the tab if connected
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && !backendConnectionLostRef.current) {
        pollStatusAndEvents();
        pollSensors();
      }
    };
    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      isPolling = false;
      if (eventsTimerRef.current) clearInterval(eventsTimerRef.current);
      if (sensorTimerRef.current) clearInterval(sensorTimerRef.current);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, []);

  const handleStart = async () => {
    setIsStarting(true);
    setActionError(null);
    setActionSuccess(null);

    try {
      if (isLocalClient) {
        const res = await api.startCapture(selectedInterface || undefined);
        if (res.success) {
          setActionSuccess(res.message);
          const newStatus = await api.getCaptureStatus();
          setCaptureStatus(newStatus);
          if (onRefreshParent) onRefreshParent();
        }
      } else {
        if (!activeRemoteSensor) {
          setShowEnrollModal(true);
          return;
        }
        const res = await api.controlSensor(activeRemoteSensor.sensor_id, 'START', undefined);
        if (res.success) {
          setActionSuccess(res.message);
          const list = await api.getEnrolledSensors();
          setEnrolledSensors(list);
          if (onRefreshParent) onRefreshParent();
        }
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
      if (isLocalClient) {
        const res = await api.stopCapture();
        if (res.success) {
          setActionSuccess(res.message);
          const newStatus = await api.getCaptureStatus();
          setCaptureStatus(newStatus);
          if (onRefreshParent) onRefreshParent();
        }
      } else {
        if (!activeRemoteSensor) return;
        const res = await api.controlSensor(activeRemoteSensor.sensor_id, 'STOP');
        if (res.success) {
          setActionSuccess(res.message);
          const list = await api.getEnrolledSensors();
          setEnrolledSensors(list);
          if (onRefreshParent) onRefreshParent();
        }
      }
    } catch (err: any) {
      setActionError(err.message || 'Failed to stop capture.');
    } finally {
      setIsStopping(false);
    }
  };

  const handleEnrollSensor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSensorId.trim() || !newSensorName.trim()) return;
    try {
      setActionError(null);
      const res = await api.enrollSensor({
        sensor_id: newSensorId.trim().toLowerCase(),
        name: newSensorName.trim()
      });
      setEnrollResult(res);
      setNewSensorId('');
      setNewSensorName('');
      const list = await api.getEnrolledSensors();
      setEnrolledSensors(list);
    } catch (err: any) {
      setActionError(err.message || 'Failed to enroll sensor.');
    }
  };

  const handleRevokeSensor = async (sensorId: string) => {
    if (!window.confirm(`Revoke sensor '${sensorId}'? Telemetry from this device will be rejected.`)) return;
    try {
      setActionError(null);
      await api.revokeSensor(sensorId);
      const list = await api.getEnrolledSensors();
      setEnrolledSensors(list);
      setActionSuccess(`Sensor '${sensorId}' has been revoked.`);
    } catch (err: any) {
      setActionError(err.message || 'Failed to revoke sensor.');
    }
  };

  const handleCopyKey = () => {
    if (enrollResult?.api_key) {
      navigator.clipboard.writeText(enrollResult.api_key);
      setCopiedKey(true);
      setTimeout(() => setCopiedKey(false), 2000);
    }
  };

  const handleCopyElevatedCmd = () => {
    const cmd = `powershell -ExecutionPolicy Bypass -File scripts/launch_sensor_elevated.ps1`;
    navigator.clipboard.writeText(cmd);
    setCopiedCmd(true);
    setTimeout(() => setCopiedCmd(false), 2000);
  };

  const isWindows = typeof navigator !== 'undefined' && /Win/i.test(navigator.userAgent);
  const isMac = typeof navigator !== 'undefined' && /Mac/i.test(navigator.userAgent);
  const isLinux = typeof navigator !== 'undefined' && /Linux/i.test(navigator.userAgent);

  const handleDownloadPackage = async (sensorId?: string, apiKey?: string) => {
    try {
      setIsDownloadingPackage(true);
      setActionError(null);
      const { blob, filename } = await api.downloadWindowsSensor(sensorId, apiKey);
      downloadBlob(blob, filename);
      setActionSuccess(`Sensor package '${filename}' downloaded successfully.`);
    } catch (err: any) {
      setActionError(err.message || 'Failed to download sensor package.');
    } finally {
      setIsDownloadingPackage(false);
    }
  };

  // Determine current Diagnostic State across all 7 required dimensions
  const computeDiagnosticState = (): DiagnosticState => {
    if (backendConnectionLost) {
      return 'BACKEND_CONNECTION_LOST';
    }
    if (captureStatus?.busy_by_other_user) {
      return 'OCCUPIED_BY_ANOTHER_USER';
    }
    if (captureStatus?.sensor_installed === false || (interfaces.length === 0 && !isLoading)) {
      return 'SENSOR_NOT_INSTALLED';
    }
    const errText = (captureStatus?.error_message || actionError || '').toLowerCase();
    if (
      captureStatus?.diagnostic_state === 'PERMISSION_REQUIRED' ||
      errText.includes('permission') ||
      errText.includes('access is denied') ||
      errText.includes('administrator') ||
      errText.includes('elevation')
    ) {
      return 'PERMISSION_REQUIRED';
    }
    if (
      captureStatus?.diagnostic_state === 'INTERFACE_UNAVAILABLE' ||
      (selectedInterface && !interfaces.some(i => i.name === selectedInterface) && interfaces.length > 0)
    ) {
      return 'INTERFACE_UNAVAILABLE';
    }
    if (captureStatus?.state === 'ACTIVE') {
      const pkts = captureStatus.packets_captured ?? 0;
      const uptime = captureStatus.uptime_seconds ?? 0;
      if (pkts === 0 && uptime >= 2) {
        return 'RUNNING_NO_PACKETS';
      }
      return 'ACTIVE_TELEMETRY';
    }
    return 'SENSOR_OFFLINE';
  };

  const isLocalClient = captureStatus?.is_local_client !== false;
  const isOwner = captureStatus?.is_owner !== false;

  const activeRemoteSensor =
    enrolledSensors.find(s => s.sensor_id === selectedRemoteSensorId) ||
    enrolledSensors.find(s => s.status === 'ACTIVE') ||
    enrolledSensors[0] ||
    null;

  const isRemoteOnline = Boolean(
    activeRemoteSensor &&
    activeRemoteSensor.status === 'ACTIVE' &&
    activeRemoteSensor.last_seen_at &&
    (Date.now() - new Date(activeRemoteSensor.last_seen_at).getTime()) < 90000
  );

  const isRemoteConfirmedRunning = Boolean(
    isRemoteOnline &&
    activeRemoteSensor?.actual_state === 'RUNNING'
  );

  const isRemoteRunningNoPackets = Boolean(
    isRemoteConfirmedRunning &&
    (activeRemoteSensor?.packets_uploaded ?? 0) === 0
  );

  const isRemoteCommandPending = Boolean(
    isRemoteOnline &&
    activeRemoteSensor?.target_state === 'RUNNING' &&
    activeRemoteSensor?.actual_state !== 'RUNNING'
  );

  const isRemoteError = Boolean(
    activeRemoteSensor &&
    (activeRemoteSensor.actual_state === 'ERROR' || activeRemoteSensor.actual_state === 'PERMISSION_REQUIRED')
  );

  const diagnosticState = computeDiagnosticState();
  const isCapturing = isLocalClient
    ? (diagnosticState === 'ACTIVE_TELEMETRY' || diagnosticState === 'RUNNING_NO_PACKETS')
    : isRemoteConfirmedRunning;

  const getStatusBadge = () => {
    if (backendConnectionLost) {
      return (
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] font-mono text-xs font-bold animate-pulse">
          <WifiOff className="w-3.5 h-3.5" />
          <span>BACKEND CONNECTION LOST</span>
        </div>
      );
    }

    if (!isLocalClient) {
      if (isRemoteError) {
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] font-mono text-xs font-bold">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>PERMISSION / DRIVER ERROR</span>
          </div>
        );
      }
      if (isRemoteConfirmedRunning) {
        if (isRemoteRunningNoPackets) {
          return (
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#39D7FF]/15 border border-[#39D7FF]/40 text-[#39D7FF] font-mono text-xs font-bold">
              <span className="w-2.5 h-2.5 rounded-full bg-[#39D7FF] animate-pulse" />
              <span>LISTENING (0 PPS / NO PACKETS)</span>
            </div>
          );
        }
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#7DDB52]/15 border border-[#7DDB52]/40 text-[#7DDB52] font-mono text-xs font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-[#7DDB52] animate-pulse" />
            <span>REMOTE AGENT CAPTURE ACTIVE</span>
          </div>
        );
      }
      if (isRemoteCommandPending) {
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FFB800]/15 border border-[#FFB800]/40 text-[#FFB800] font-mono text-xs font-bold animate-pulse">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FFB800]" />
            <span>STARTING (AWAITING AGENT)...</span>
          </div>
        );
      }
      if (isRemoteOnline) {
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#39D7FF]/15 border border-[#39D7FF]/40 text-[#39D7FF] font-mono text-xs font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-[#39D7FF]" />
            <span>REMOTE AGENT STANDBY</span>
          </div>
        );
      }
      return (
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#A5A5BE]/15 border border-[#A5A5BE]/40 text-[#A5A5BE] font-mono text-xs font-bold">
          <span className="w-2.5 h-2.5 rounded-full bg-[#A5A5BE]" />
          <span>AGENT OFFLINE</span>
        </div>
      );
    }

    switch (diagnosticState) {
      case 'BACKEND_CONNECTION_LOST':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] font-mono text-xs font-bold animate-pulse">
            <WifiOff className="w-3.5 h-3.5" />
            <span>BACKEND CONNECTION LOST</span>
          </div>
        );
      case 'SENSOR_NOT_INSTALLED':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FFB800]/15 border border-[#FFB800]/40 text-[#FFB800] font-mono text-xs font-bold">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span>NPCAP DRIVER NOT INSTALLED</span>
          </div>
        );
      case 'PERMISSION_REQUIRED':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] font-mono text-xs font-bold">
            <ShieldAlert className="w-3.5 h-3.5" />
            <span>ELEVATION REQUIRED</span>
          </div>
        );
      case 'INTERFACE_UNAVAILABLE':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] font-mono text-xs font-bold">
            <AlertCircle className="w-3.5 h-3.5" />
            <span>INTERFACE UNAVAILABLE</span>
          </div>
        );
      case 'RUNNING_NO_PACKETS':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#39D7FF]/15 border border-[#39D7FF]/40 text-[#39D7FF] font-mono text-xs font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-[#39D7FF] animate-pulse" />
            <span>LISTENING (0 PPS)</span>
          </div>
        );
      case 'ACTIVE_TELEMETRY':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#7DDB52]/15 border border-[#7DDB52]/40 text-[#7DDB52] font-mono text-xs font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-[#7DDB52] animate-pulse" />
            <span>ACTIVE PASSIVE CAPTURE</span>
          </div>
        );
      case 'OCCUPIED_BY_ANOTHER_USER':
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FFB800]/15 border border-[#FFB800]/40 text-[#FFB800] font-mono text-xs font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-[#FFB800]" />
            <span>LOCAL ADAPTER IN USE</span>
          </div>
        );
      case 'SENSOR_OFFLINE':
      default:
        return (
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#A5A5BE]/15 border border-[#A5A5BE]/40 text-[#A5A5BE] font-mono text-xs font-bold">
            <span className="w-2.5 h-2.5 rounded-full bg-[#A5A5BE]" />
            <span>SENSOR STANDBY</span>
          </div>
        );
    }
  };

  // Filter events by source
  const localEventsCount = events.filter(e => e.source === 'LOCAL RX' || !e.source).length;
  const remoteEventsCount = events.filter(e => e.source?.startsWith('SENSOR:') || e.source === 'REMOTE' || Boolean(e.sensor_id)).length;

  const filteredEvents = events.filter((evt) => {
    const isRemote = evt.source?.startsWith('SENSOR:') || evt.source === 'REMOTE' || Boolean(evt.sensor_id);
    if (sourceFilter === 'local') return !isRemote;
    if (sourceFilter === 'remote') {
      if (!isRemote) return false;
      if (selectedSensorFilter) return evt.sensor_id === selectedSensorFilter;
      return true;
    }
    return true;
  });

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
              {isLocalClient
                ? isCapturing
                  ? `Passive capture active on ${captureStatus?.interface || selectedInterface}`
                  : 'Passive network sensor standby'
                : isCapturing
                ? `Remote sensor active on ${activeRemoteSensor?.name || 'workstation'}`
                : isRemoteCommandPending
                ? `Starting remote sensor on ${activeRemoteSensor?.name || 'workstation'}...`
                : isRemoteOnline
                ? `Remote sensor standby on ${activeRemoteSensor?.name || 'workstation'}`
                : 'Remote workstation sensor offline'}
            </span>
            <span className="text-[11px] text-[#A5A5BE] font-sans">
              Individual user isolation enabled. Metadata-only flow capture. Zero packet payloads retained.
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0 flex-wrap">
          <button
            onClick={() => setShowEnrollModal(true)}
            className="px-3 py-1.5 rounded-xl bg-[#7B2CBF]/20 hover:bg-[#7B2CBF]/30 border border-[#7B2CBF]/50 text-[#D8BBFF] text-xs font-mono font-semibold flex items-center gap-1.5 transition-all cursor-pointer"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Enroll My Computer</span>
          </button>
          {getStatusBadge()}
        </div>
      </div>

      {/* Diagnostic State 1: Sensor Not Installed Banner */}
      {isLocalClient && diagnosticState === 'SENSOR_NOT_INSTALLED' && (
        <div className="p-4 rounded-2xl bg-[#FFB800]/10 border border-[#FFB800]/30 text-xs font-mono text-[#FFB800] flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-lg">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 shrink-0 mt-0.5 text-[#FFB800]" />
            <div>
              <span className="font-bold block text-[#F5F5F7] mb-0.5">Npcap Packet Driver Not Detected</span>
              <span className="text-[#A5A5BE] font-sans text-xs">
                Passive packet capture on Windows requires the Npcap OEM or Community driver. Please install Npcap with "Install Npcap in WinPcap API-compatible Mode" selected.
              </span>
            </div>
          </div>
          <a
            href="https://npcap.com/#download"
            target="_blank"
            rel="noreferrer"
            className="px-3.5 py-2 rounded-xl bg-[#FFB800] text-[#07072B] font-bold shrink-0 hover:bg-[#FFC933] transition-all cursor-pointer"
          >
            Download Npcap
          </a>
        </div>
      )}

      {/* Diagnostic State 3: Elevation Required Banner */}
      {diagnosticState === 'PERMISSION_REQUIRED' && (
        <div className="p-4 rounded-2xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 text-xs font-mono text-[#FF4D5A] space-y-2.5 shadow-lg">
          <div className="flex items-start gap-2.5">
            <ShieldAlert className="w-5 h-5 shrink-0 mt-0.5 text-[#FF4D5A]" />
            <div>
              <span className="font-bold text-[#F5F5F7] block text-sm">Administrator Elevation Required for Packet Capture</span>
              <span className="text-[#A5A5BE] font-sans text-xs block mt-0.5">
                Windows/Npcap requires elevated privileges to bind to raw network adapters. Rather than granting full server admin rights to your web account, launch the approved local sensor launcher with elevation:
              </span>
            </div>
          </div>
          <div className="p-2.5 rounded-xl bg-[#07072B] border border-[#242452] text-[11px] text-[#39D7FF] font-mono flex items-center justify-between gap-2">
            <code className="truncate">powershell -ExecutionPolicy Bypass -File scripts/launch_sensor_elevated.ps1</code>
            <button
              onClick={handleCopyElevatedCmd}
              className="px-2.5 py-1 rounded-lg bg-[#39D7FF]/20 text-[#39D7FF] hover:bg-[#39D7FF]/30 text-[10px] font-semibold flex items-center gap-1 cursor-pointer shrink-0"
            >
              {copiedCmd ? <Check className="w-3.5 h-3.5 text-[#7DDB52]" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedCmd ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
        </div>
      )}

      {/* Diagnostic State 4: Interface Unavailable Banner */}
      {diagnosticState === 'INTERFACE_UNAVAILABLE' && (
        <div className="p-3.5 rounded-xl bg-[#FF4D5A]/10 border border-[#FF4D5A]/30 text-xs font-mono text-[#FF4D5A] flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 shrink-0 text-[#FF4D5A]" />
          <div>
            <span className="font-bold text-[#F5F5F7] block">Selected Interface Unavailable</span>
            <span className="text-[#A5A5BE] text-[11px] font-sans">
              The adapter '{selectedInterface}' is disconnected or has no assigned IP address. Please choose an active interface from the dropdown below.
            </span>
          </div>
        </div>
      )}

      {/* Diagnostic State 5: Running But No Packets Observed */}
      {diagnosticState === 'RUNNING_NO_PACKETS' && (
        <div className="p-3.5 rounded-xl bg-[#39D7FF]/10 border border-[#39D7FF]/30 text-xs font-mono text-[#39D7FF] flex items-center gap-2.5">
          <Radio className="w-4 h-4 shrink-0 animate-pulse text-[#39D7FF]" />
          <div>
            <span className="font-bold text-[#F5F5F7] block">Sensor Running • Listening on {selectedInterface}</span>
            <span className="text-[#A5A5BE] text-[11px] font-sans">
              Sniffer worker is active, but 0 packets have been observed on this interface yet (0 pps). Open a web browser or run network traffic on this machine to observe live flows.
            </span>
          </div>
        </div>
      )}

      {/* Diagnostic State 7: Backend Connection Lost */}
      {diagnosticState === 'BACKEND_CONNECTION_LOST' && (
        <div className="p-4 rounded-2xl bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-xs font-mono text-[#FF4D5A] flex items-center gap-3">
          <WifiOff className="w-5 h-5 shrink-0 text-[#FF4D5A] animate-pulse" />
          <div>
            <span className="font-bold text-[#F5F5F7] block text-sm">Backend Connection Lost</span>
            <span className="text-[#A5A5BE] font-sans text-xs">
              Unable to reach the ThreatTrack backend server at {window.location.origin}. Polling will automatically reconnect as soon as the service resumes.
            </span>
          </div>
        </div>
      )}

      {/* Occupied By Another User Alert */}
      {diagnosticState === 'OCCUPIED_BY_ANOTHER_USER' && (
        <div className="p-3.5 rounded-xl bg-[#FFB800]/10 border border-[#FFB800]/30 text-xs font-mono text-[#FFB800] flex items-center gap-2.5">
          <AlertCircle className="w-4 h-4 shrink-0 text-[#FFB800]" />
          <div>
            <span className="font-bold text-[#F5F5F7] block">Local Network Adapter Currently In Use</span>
            <span className="text-[#A5A5BE] text-[11px] font-sans">
              Another local user currently has an active packet capture session. Strict per-user traffic isolation prevents concurrent sniffing on the same hardware adapter.
            </span>
          </div>
        </div>
      )}

      {/* Remote Workstation Notice if client is not localhost */}
      {!isLocalClient && (
        <div className="p-3.5 rounded-xl bg-[#7B2CBF]/15 border border-[#7B2CBF]/40 text-xs font-mono text-[#D8BBFF] flex items-start sm:items-center justify-between gap-3 flex-col sm:flex-row">
          <div className="flex items-start gap-2.5">
            <Laptop className="w-5 h-5 text-[#39D7FF] shrink-0 mt-0.5" />
            <div>
              <span className="font-bold text-[#F5F5F7] block">Remote Client Connected</span>
              <span className="text-[#A5A5BE] font-sans text-xs">
                To capture and monitor network traffic from this workstation, run the ThreatTrack Local Sensor agent on this machine with your personal API key.
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {isWindows && (
              <button
                onClick={() => handleDownloadPackage()}
                disabled={isDownloadingPackage}
                className="px-3 py-1.5 rounded-xl bg-[#39D7FF]/20 hover:bg-[#39D7FF]/30 border border-[#39D7FF]/50 text-[#39D7FF] text-xs font-semibold flex items-center gap-1.5 cursor-pointer"
              >
                <Download className="w-3.5 h-3.5" />
                <span>{isDownloadingPackage ? 'Downloading...' : 'Download Sensor (.zip)'}</span>
              </button>
            )}
            <button
              onClick={() => setShowEnrollModal(true)}
              className="px-3 py-1.5 rounded-xl bg-[#7B2CBF] text-[#F5F5F7] hover:bg-[#8A38D4] text-xs font-semibold cursor-pointer shrink-0"
            >
              Get Sensor Setup
            </button>
          </div>
        </div>
      )}

      {/* Action alerts */}
      {actionError && diagnosticState !== 'PERMISSION_REQUIRED' && (
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

      {/* Enrollment Modal */}
      {showEnrollModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg rounded-2xl bg-[#0D0D36] border border-[#242452] p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between border-b border-[#242452] pb-3">
              <h3 className="text-base font-heading font-bold text-[#F5F5F7] flex items-center gap-2">
                <Laptop className="w-5 h-5 text-[#39D7FF]" />
                <span>Enroll Local Computer / Sensor</span>
              </h3>
              <button
                onClick={() => {
                  setShowEnrollModal(false);
                  setEnrollResult(null);
                }}
                className="text-[#A5A5BE] hover:text-[#F5F5F7] text-sm"
              >
                ✕
              </button>
            </div>

            {!enrollResult ? (
              <form onSubmit={handleEnrollSensor} className="space-y-4 text-xs font-mono">
                <p className="text-[#A5A5BE]">
                  Generate a revocable, cryptographically secure API key for your computer's local sensor.
                  Telemetry transmitted by this sensor will be strictly isolated and attributed to your account ({user?.email}).
                </p>

                <div>
                  <label className="text-[11px] text-[#A5A5BE] block mb-1">Sensor Identifier (Slug)</label>
                  <input
                    type="text"
                    value={newSensorId}
                    onChange={(e) => setNewSensorId(e.target.value)}
                    placeholder="e.g. sensor-my-laptop-01"
                    className="w-full px-3 py-2 rounded-xl bg-[#07072B] border border-[#242452] text-[#F5F5F7] focus:border-[#39D7FF] outline-none"
                    required
                  />
                </div>

                <div>
                  <label className="text-[11px] text-[#A5A5BE] block mb-1">Device Label / Computer Name</label>
                  <input
                    type="text"
                    value={newSensorName}
                    onChange={(e) => setNewSensorName(e.target.value)}
                    placeholder="e.g. My Workstation (Windows 11)"
                    className="w-full px-3 py-2 rounded-xl bg-[#07072B] border border-[#242452] text-[#F5F5F7] focus:border-[#39D7FF] outline-none"
                    required
                  />
                </div>

                <div className="flex justify-end gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setShowEnrollModal(false)}
                    className="px-4 py-2 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE]"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    className="px-4 py-2 rounded-xl bg-gradient-to-r from-[#39D7FF] to-[#00A3FF] text-[#05051F] font-bold"
                  >
                    Generate Sensor Credential
                  </button>
                </div>
              </form>
            ) : (
              <div className="space-y-4 text-xs font-mono">
                <div className="p-3 rounded-xl bg-[#7DDB52]/10 border border-[#7DDB52]/30 text-[#7DDB52] flex items-center gap-2">
                  <CheckCircle2 className="w-5 h-5 shrink-0" />
                  <span>Sensor enrolled successfully! Store your API key now.</span>
                </div>

                <div>
                  <label className="text-[11px] text-[#A5A5BE] block mb-1">Sensor ID</label>
                  <div className="p-2.5 rounded-xl bg-[#07072B] border border-[#242452] text-[#F5F5F7]">
                    {enrollResult.sensor.sensor_id}
                  </div>
                </div>

                <div>
                  <label className="text-[11px] text-[#A5A5BE] block mb-1">Sensor API Key (Secret)</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="text"
                      readOnly
                      value={enrollResult.api_key}
                      className="w-full p-2.5 rounded-xl bg-[#07072B] border border-[#39D7FF]/50 text-[#A8F500] font-mono select-all outline-none"
                    />
                    <button
                      type="button"
                      onClick={handleCopyKey}
                      className="px-3 py-2.5 rounded-xl bg-[#39D7FF]/20 hover:bg-[#39D7FF]/30 border border-[#39D7FF]/50 text-[#39D7FF] flex items-center gap-1 shrink-0 cursor-pointer"
                    >
                      {copiedKey ? <Check className="w-4 h-4 text-[#7DDB52]" /> : <Copy className="w-4 h-4" />}
                      <span>{copiedKey ? 'Copied' : 'Copy'}</span>
                    </button>
                  </div>
                </div>

                {/* Operating System Compatibility Notice */}
                {!isWindows && (
                  <div className="p-3 rounded-xl bg-[#FFB800]/10 border border-[#FFB800]/30 text-xs font-mono text-[#FFB800] space-y-1">
                    <div className="font-bold flex items-center gap-1.5">
                      <AlertTriangle className="w-4 h-4 text-[#FFB800] shrink-0" />
                      <span>{isMac ? 'macOS' : isLinux ? 'Linux' : 'Non-Windows'} Client Detected</span>
                    </div>
                    <p className="text-[#A5A5BE] font-sans text-[11px] leading-relaxed">
                      ThreatTrack Local Packet Capture Agent currently supports Windows 10 and 11 with the Npcap driver. Native client-side sniffing on macOS and Linux is in active development. You can monitor Windows workstations from this account, or inspect recorded flows.
                    </p>
                  </div>
                )}

                {/* 1-Click Zero-Command Windows Package Download */}
                <div className="p-3.5 rounded-xl bg-[#10103D] border border-[#39D7FF]/30 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-[#39D7FF] font-semibold text-xs flex items-center gap-1.5">
                      <Download className="w-4 h-4" />
                      <span>1-Click Windows Sensor Package</span>
                    </span>
                    <span className="text-[10px] text-[#7DDB52] bg-[#7DDB52]/10 border border-[#7DDB52]/30 px-2 py-0.5 rounded-full font-bold">
                      Pre-Configured
                    </span>
                  </div>
                  <p className="text-[#A5A5BE] text-[11px] font-sans">
                    Includes your API key pre-filled in <code>sensor_config.json</code> and a double-clickable <code>start_sensor.bat</code> launcher that handles Administrator UAC automatically.
                  </p>
                  <button
                    type="button"
                    disabled={isDownloadingPackage}
                    onClick={() => handleDownloadPackage(enrollResult.sensor.sensor_id, enrollResult.api_key)}
                    className="w-full py-2.5 px-4 rounded-xl bg-gradient-to-r from-[#39D7FF] to-[#00A3FF] text-[#05051F] font-bold text-xs flex items-center justify-center gap-2 hover:opacity-90 transition-all cursor-pointer shadow-lg"
                  >
                    <Download className="w-4 h-4" />
                    <span>{isDownloadingPackage ? 'Preparing Sensor Package...' : 'Download Windows Sensor Package (.zip)'}</span>
                  </button>
                </div>

                {/* 3-Step Setup Instructions */}
                <div className="p-3 rounded-xl bg-[#07072B] border border-[#242452] text-[11px] text-[#A5A5BE] space-y-2">
                  <span className="text-[#F5F5F7] font-semibold block">Quick 3-Step Setup:</span>
                  <ol className="list-decimal list-inside space-y-1 font-sans text-[11px]">
                    <li>Ensure <a href="https://npcap.com/#download" target="_blank" rel="noreferrer" className="text-[#39D7FF] underline">Npcap</a> is installed with WinPcap API-compatible mode enabled.</li>
                    <li>Extract the downloaded <code>ThreatTrack-Sensor.zip</code> to any folder.</li>
                    <li>Double-click <code>start_sensor.bat</code> and accept the Windows UAC elevation prompt.</li>
                  </ol>
                </div>

                {/* Manual Terminal Commands (For Developers) */}
                <details className="text-[11px] text-[#A5A5BE] space-y-2 cursor-pointer">
                  <summary className="text-[#39D7FF] hover:underline font-semibold">
                    Show advanced terminal launch commands
                  </summary>
                  <div className="space-y-2 pt-2">
                    <div className="space-y-1">
                      <span className="text-[10px] text-[#A5A5BE] block">Standard Runner:</span>
                      <code className="block p-1.5 rounded bg-[#10103D] text-[10px] text-[#F5F5F7] overflow-x-auto">
                        python scripts/run_sensor.py --interface "{selectedInterface || 'Wi-Fi 3'}" --backend-url "{window.location.origin}" --api-key "{enrollResult.api_key}" --sensor-id "{enrollResult.sensor.sensor_id}"
                      </code>
                    </div>
                    <div className="space-y-1">
                      <span className="text-[10px] text-[#A5A5BE] block">Approved Elevated Windows Launcher (Least Privileges):</span>
                      <code className="block p-1.5 rounded bg-[#10103D] text-[10px] text-[#A8F500] overflow-x-auto">
                        powershell -ExecutionPolicy Bypass -File scripts/launch_sensor_elevated.ps1 -Interface "{selectedInterface || 'Wi-Fi 3'}" -BackendUrl "{window.location.origin}" -ApiKey "{enrollResult.api_key}" -SensorId "{enrollResult.sensor.sensor_id}"
                      </code>
                    </div>
                  </div>
                </details>

                <div className="flex justify-end pt-2">
                  <button
                    type="button"
                    onClick={() => {
                      setShowEnrollModal(false);
                      setEnrollResult(null);
                    }}
                    className="px-4 py-2 rounded-xl bg-gradient-to-r from-[#39D7FF] to-[#00A3FF] text-[#05051F] font-bold"
                  >
                    Done
                  </button>
                </div>
              </div>
            )}
          </div>
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

            {/* Interface / Remote Sensor Selector Dropdown */}
            <div className="mb-4">
              <label className="block text-[11px] font-mono text-[#A5A5BE] mb-1.5 uppercase">
                {isLocalClient ? 'Target Capture Interface' : 'Target Enrolled Sensor Device'}
              </label>
              {isLocalClient ? (
                <select
                  value={selectedInterface}
                  onChange={(e) => setSelectedInterface(e.target.value)}
                  disabled={isCapturing || isLoading}
                  className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF] disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {interfaces.map((iface) => (
                    <option key={iface.name} value={iface.name}>
                      {iface.name} {iface.ip ? `(${iface.ip})` : iface.ips && iface.ips.length > 0 ? `(${iface.ips.join(', ')})` : '(No IP)'} {iface.is_active ? '• Active' : ''}
                    </option>
                  ))}
                </select>
              ) : (
                <select
                  value={selectedRemoteSensorId}
                  onChange={(e) => setSelectedRemoteSensorId(e.target.value)}
                  disabled={isCapturing || isRemoteCommandPending}
                  className="w-full bg-[#07072B] border border-[#242452] rounded-xl px-3 py-2 text-xs font-mono text-[#F5F5F7] focus:outline-none focus:border-[#39D7FF] disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {enrolledSensors.length === 0 ? (
                    <option value="">No enrolled sensors (Click Enroll My Computer)</option>
                  ) : (
                    enrolledSensors.map((s) => (
                      <option key={s.sensor_id} value={s.sensor_id}>
                        {s.name} ({s.sensor_id}) • {s.status === 'ACTIVE' ? (s.last_seen_at && (Date.now() - new Date(s.last_seen_at).getTime() < 90000) ? 'Online' : 'Standby') : 'Revoked'}
                      </option>
                    ))
                  )}
                </select>
              )}
            </div>

            <p className="text-xs text-[#A5A5BE] font-sans mb-5 leading-relaxed">
              {isLocalClient
                ? 'Monitors packet metadata on your active network adapter. Captured flows and detection alerts are strictly isolated and attributed to your user account.'
                : 'Monitors packet metadata transmitted by your enrolled local Windows sensor agent. Commands securely control your sensor without accessing server interfaces.'}
            </p>

            <div className="grid grid-cols-2 gap-3 mb-4">
              {isCapturing ? (
                <button
                  onClick={handleStop}
                  disabled={isStopping || (isLocalClient && !isOwner && !isAdmin)}
                  title={isLocalClient && !isOwner && !isAdmin ? "Only session owner or administrator can stop this capture" : undefined}
                  className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#FF4D5A]/20 hover:bg-[#FF4D5A]/30 border border-[#FF4D5A]/50 text-[#FF4D5A] text-xs font-mono font-bold transition-all cursor-pointer shadow-md shadow-[#FF4D5A]/10 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Square className="w-4 h-4" />
                  <span>{isStopping ? 'Stopping...' : 'Stop Monitoring'}</span>
                </button>
              ) : (
                <button
                  onClick={handleStart}
                  disabled={
                    isStarting ||
                    isLoading ||
                    (isLocalClient && Boolean(captureStatus?.busy_by_other_user)) ||
                    (!isLocalClient && isRemoteCommandPending)
                  }
                  title={
                    !isLocalClient
                      ? !activeRemoteSensor
                        ? "Enroll local computer sensor to start monitoring"
                        : `Start capture on sensor '${activeRemoteSensor.name}'`
                      : undefined
                  }
                  className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#A8F500] hover:bg-[#B7FF19] text-[#07072B] text-xs font-mono font-bold transition-all cursor-pointer shadow-md shadow-[#A8F500]/20 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Play className="w-4 h-4 fill-current" />
                  <span>
                    {isStarting
                      ? 'Starting...'
                      : !isLocalClient && isRemoteCommandPending
                      ? 'Awaiting Agent...'
                      : !isLocalClient && !activeRemoteSensor
                      ? 'Enroll Sensor'
                      : 'Start Monitoring'}
                  </span>
                </button>
              )}

              <button
                onClick={async () => {
                  setBackendConnectionLost(false);
                  backendConnectionLostRef.current = false;
                  try {
                    const [statusData, localEvents, remoteEvents, sensorList] = await Promise.all([
                      api.getCaptureStatus(),
                      api.getRecentLiveEvents(30).catch(() => []),
                      api.getRemoteSensorEvents(undefined, 30).catch(() => []),
                      api.getEnrolledSensors().catch(() => [])
                    ]);
                    if (statusData) setCaptureStatus(statusData);
                    if (sensorList) setEnrolledSensors(sensorList);
                    const taggedLocal = (localEvents || []).map(e => ({ ...e, source: 'LOCAL RX' }));
                    const taggedRemote = (remoteEvents || []).map(e => ({
                      ...e,
                      source: e.source || (e.sensor_id ? `SENSOR: ${e.sensor_id}` : 'REMOTE')
                    }));
                    setEvents([...taggedLocal, ...taggedRemote].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)));
                  } catch {
                    setBackendConnectionLost(true);
                    backendConnectionLostRef.current = true;
                  }
                }}
                className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] text-xs font-mono font-semibold transition-all cursor-pointer"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Refresh</span>
              </button>
            </div>
          </div>

          <div className="pt-3 border-t border-[#242452] flex items-center justify-between text-xs font-mono text-[#A5A5BE]">
            <span>Safety State:</span>
            <span className="text-[#7DDB52] font-semibold">Strict Passive (Zero Injection)</span>
          </div>
        </div>

        {/* Live Counters & Rate Metering (2 cols) */}
        <div className="lg:col-span-2 rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-4">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider flex items-center gap-2">
                <Activity className="w-4 h-4 text-[#39D7FF]" />
                Live Network Flow Telemetry
              </span>
              <span className="text-xs font-mono text-[#A8F500]">
                {captureStatus?.packets_dropped ? `${captureStatus.packets_dropped} dropped` : '0 Packet Loss'}
              </span>
            </div>

            {/* Metric Cards Grid */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-6">
              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Packets Captured</span>
                <span className="text-2xl font-heading font-extrabold text-[#F5F5F7] mt-1 block">
                  {(isLocalClient ? (captureStatus?.packets_captured ?? 0) : (activeRemoteSensor?.packets_uploaded ?? 0)).toLocaleString()}
                </span>
                <span className="text-[10px] font-mono text-[#7DDB52]">Observed Packets</span>
              </div>

              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Flows Created</span>
                <span className="text-2xl font-heading font-extrabold text-[#39D7FF] mt-1 block">
                  {(isLocalClient ? (captureStatus?.flows_created ?? 0) : (activeRemoteSensor?.flows_uploaded ?? 0)).toLocaleString()}
                </span>
                <span className="text-[10px] font-mono text-[#39D7FF]">Aggregated</span>
              </div>

              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Threats Detected</span>
                <span className="text-2xl font-heading font-extrabold text-[#FF4D5A] mt-1 block">
                  {isLocalClient ? (captureStatus?.threats_detected ?? 0) : (activeRemoteSensor?.alerts_uploaded ?? 0)}
                </span>
                <span className="text-[10px] font-mono text-[#FF4D5A]">Alerts Generated</span>
              </div>

              <div className="p-3.5 rounded-xl bg-[#07072B] border border-[#242452]">
                <span className="text-[10px] font-mono text-[#A5A5BE] block uppercase">Packet Rate</span>
                <span className="text-2xl font-heading font-extrabold text-[#A8F500] mt-1 block">
                  {(isLocalClient ? (captureStatus?.current_pps ?? 0) : (isRemoteConfirmedRunning ? 10 : 0)).toLocaleString()}
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

      {/* Split: Live Flow Stream Feed + Capture Hardware & Remote Sensor Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Events Feed (2 Cols) */}
        <div className="lg:col-span-2 rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <h4 className="text-sm font-heading font-semibold text-[#F5F5F7] flex items-center gap-2">
                <span>Recent Network Events</span>
                {isCapturing && (
                  <span className="w-2 h-2 rounded-full bg-[#7DDB52] animate-ping" />
                )}
              </h4>
              <p className="text-[11px] text-[#A5A5BE]">
                Live traffic evaluated by FlowBuilder and ML Threat Engine with source attribution
              </p>
            </div>

            {/* Source Filtering Pills */}
            <div className="flex items-center gap-1.5 p-1 rounded-xl bg-[#07072B] border border-[#242452] text-[11px] font-mono">
              <button
                onClick={() => setSourceFilter('all')}
                className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
                  sourceFilter === 'all'
                    ? 'bg-[#39D7FF] text-[#05051F] font-bold'
                    : 'text-[#A5A5BE] hover:text-[#F5F5F7]'
                }`}
              >
                All ({events.length})
              </button>
              <button
                onClick={() => setSourceFilter('local')}
                className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
                  sourceFilter === 'local'
                    ? 'bg-[#39D7FF] text-[#05051F] font-bold'
                    : 'text-[#A5A5BE] hover:text-[#F5F5F7]'
                }`}
              >
                Local RX ({localEventsCount})
              </button>
              <button
                onClick={() => setSourceFilter('remote')}
                className={`px-2.5 py-1 rounded-lg transition-all cursor-pointer ${
                  sourceFilter === 'remote'
                    ? 'bg-[#7B2CBF] text-[#F5F5F7] font-bold'
                    : 'text-[#A5A5BE] hover:text-[#F5F5F7]'
                }`}
              >
                Remote ({remoteEventsCount})
              </button>

              {sourceFilter === 'remote' && enrolledSensors.length > 0 && (
                <select
                  value={selectedSensorFilter}
                  onChange={(e) => setSelectedSensorFilter(e.target.value)}
                  className="bg-[#07072B] border border-[#7B2CBF]/50 rounded-lg px-2 py-0.5 text-[10px] font-mono text-[#D8BBFF] outline-none ml-1"
                >
                  <option value="">All Remote Sensors</option>
                  {enrolledSensors.map(s => (
                    <option key={s.sensor_id} value={s.sensor_id}>{s.name} ({s.sensor_id})</option>
                  ))}
                </select>
              )}
            </div>
          </div>

          {filteredEvents.length > 0 ? (
            <div className="space-y-2 max-h-[460px] overflow-y-auto pr-1">
              {filteredEvents.map((evt) => {
                const isThreat = evt.threat_outcome !== 'BENIGN';
                const timeFormatted = evt.timestamp
                  ? new Date(evt.timestamp > 1e11 ? evt.timestamp : evt.timestamp * 1000).toLocaleTimeString()
                  : '—';
                const isRemote = evt.source?.startsWith('SENSOR:') || evt.source === 'REMOTE' || Boolean(evt.sensor_id);

                return (
                  <div
                    key={evt.id}
                    className={`p-3 rounded-xl border transition-all text-xs font-mono flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 ${
                      isThreat
                        ? 'bg-[#FF4D5A]/10 border-[#FF4D5A]/30 hover:bg-[#FF4D5A]/15'
                        : 'bg-[#07072B] border-[#242452] hover:bg-[#15154A]/30'
                    }`}
                  >
                    <div className="flex items-center gap-2.5 flex-wrap">
                      <span className="text-[#A5A5BE] text-[11px] shrink-0">{timeFormatted}</span>

                      {/* Source Attribution Tag */}
                      <span
                        className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase shrink-0 ${
                          isRemote
                            ? 'bg-[#7B2CBF]/25 text-[#D8BBFF] border border-[#7B2CBF]/50'
                            : 'bg-[#39D7FF]/15 text-[#39D7FF] border border-[#39D7FF]/30'
                        }`}
                      >
                        {evt.source || 'LOCAL RX'}
                      </span>

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
                {sourceFilter === 'remote'
                  ? 'No remote sensor events yet'
                  : isCapturing
                  ? 'Passive capture active — waiting for network packets...'
                  : 'No network events yet'}
              </p>
              <p className="text-xs text-[#A5A5BE] mt-1 max-w-md mx-auto">
                {sourceFilter === 'remote'
                  ? 'Connect a local Windows sensor using your enrolled API key to stream live telemetry.'
                  : isCapturing
                  ? `Listening on ${captureStatus?.interface || selectedInterface}. Transmit traffic on this interface to see live flows and detection results.`
                  : 'Click "Start Monitoring" above to start passive sniffing on the selected network adapter.'}
              </p>
            </div>
          )}
        </div>

        {/* Right Column: Enrolled Reviewer Sensors + Architecture Hardware Panel */}
        <div className="space-y-6">
          {/* Enrolled Remote Sensors Card */}
          <div className="rounded-2xl bg-[#10103D]/80 border border-[#242452] p-5 shadow-xl space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-heading font-bold text-[#F5F5F7] uppercase tracking-wider flex items-center gap-2">
                <Laptop className="w-4 h-4 text-[#D8BBFF]" />
                Enrolled Sensors ({enrolledSensors.length})
              </span>
              <span className="text-xs font-mono text-[#D8BBFF]">
                {enrolledSensors.filter(s => s.status === 'ACTIVE').length} Active
              </span>
            </div>

            {enrolledSensors.length > 0 ? (
              <div className="space-y-2.5 max-h-[220px] overflow-y-auto pr-1">
                {enrolledSensors.map((s) => {
                  const now = Date.now();
                  const lastSeenTime = s.last_seen_at ? new Date(s.last_seen_at).getTime() : 0;
                  const isOnline = s.status === 'ACTIVE' && (now - lastSeenTime) < 90000;
                  const isIdle = s.status === 'ACTIVE' && !isOnline && (now - lastSeenTime) < 600000;

                  return (
                    <div
                      key={s.sensor_id}
                      className="p-3 rounded-xl bg-[#07072B] border border-[#242452] space-y-1.5 text-xs font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span
                            className={`w-2 h-2 rounded-full ${
                              s.status === 'REVOKED'
                                ? 'bg-[#FF4D5A]'
                                : isOnline
                                ? 'bg-[#7DDB52] animate-ping'
                                : isIdle
                                ? 'bg-[#FFB703]'
                                : 'bg-[#A5A5BE]'
                            }`}
                          />
                          <strong className="text-xs text-[#F5F5F7] truncate max-w-[140px]">
                            {s.name}
                          </strong>
                        </div>

                        <span
                          className={`text-[9px] px-1.5 py-0.5 rounded uppercase font-bold ${
                            s.status === 'REVOKED'
                              ? 'bg-[#FF4D5A]/20 text-[#FF4D5A]'
                              : isOnline
                              ? 'bg-[#7DDB52]/20 text-[#7DDB52]'
                              : isIdle
                              ? 'bg-[#FFB703]/20 text-[#FFB703]'
                              : 'bg-[#A5A5BE]/20 text-[#A5A5BE]'
                          }`}
                        >
                          {s.status === 'REVOKED' ? 'Revoked' : isOnline ? 'Online' : isIdle ? 'Idle' : 'Offline'}
                        </span>
                      </div>

                      <div className="text-[10px] text-[#A5A5BE] flex items-center justify-between">
                        <span>ID: {s.sensor_id}</span>
                        <span>Key: {s.api_key_prefix}</span>
                      </div>

                      <div className="pt-1.5 border-t border-[#242452]/60 flex items-center justify-between text-[10px] text-[#A5A5BE]">
                        <span>{s.flows_uploaded} flows • {s.alerts_uploaded} alerts</span>
                        {s.status === 'ACTIVE' && (
                          <button
                            onClick={() => handleRevokeSensor(s.sensor_id)}
                            className="text-[#FF4D5A] hover:underline cursor-pointer"
                          >
                            Revoke
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-[#07072B] border border-dashed border-[#242452] text-center text-xs font-mono text-[#A5A5BE]">
                <p>No local sensors enrolled for your account.</p>
                <button
                  onClick={() => setShowEnrollModal(true)}
                  className="mt-2 text-[#39D7FF] hover:underline inline-flex items-center gap-1 font-semibold cursor-pointer"
                >
                  <Plus className="w-3.5 h-3.5" />
                  <span>Enroll My Computer</span>
                </button>
              </div>
            )}
          </div>

          {/* Capture Architecture Details */}
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
    </div>
  );
};
