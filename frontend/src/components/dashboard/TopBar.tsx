import React, { useState, useEffect } from 'react';
import {
  Search,
  Clock,
  HelpCircle,
  RefreshCw,
  ArrowLeft,
  LogOut,
  User
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface TopBarProps {
  pageTitle: string;
  breadcrumbs: string[];
  searchQuery?: string;
  onSearchChange?: (q: string) => void;
  onRefresh?: () => void;
  onExitToLanding: () => void;
  onLogout?: () => void;
  captureState?: 'ACTIVE' | 'STOPPED' | 'ERROR';
  backendAvailable?: boolean;
  isRefreshing?: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  pageTitle,
  breadcrumbs,
  searchQuery,
  onSearchChange,
  onRefresh,
  onExitToLanding,
  onLogout,
  captureState = 'STOPPED',
  backendAvailable = true,
  isRefreshing = false
}) => {
  const { user, logout } = useAuth();
  const [utcTime, setUtcTime] = useState<string>('');
  const [showStatusTooltip, setShowStatusTooltip] = useState(false);

  const handleLogout = async () => {
    if (onLogout) {
      onLogout();
    } else {
      await logout();
      onExitToLanding();
    }
  };

  useEffect(() => {
    const updateTime = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().slice(17, 25) + ' UTC');
    };
    updateTime();
    const interval = setInterval(updateTime, 1000);
    return () => clearInterval(interval);
  }, []);

  const renderStatusBadge = () => {
    if (!backendAvailable) {
      return (
        <div
          onMouseEnter={() => setShowStatusTooltip(true)}
          onMouseLeave={() => setShowStatusTooltip(false)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#FF4D5A]/15 border border-[#FF4D5A]/40 text-[#FF4D5A] text-xs font-mono font-bold cursor-help transition-all"
        >
          <span className="w-2 h-2 rounded-full bg-[#FF4D5A]" />
          <span className="hidden sm:inline">BACKEND OFFLINE</span>
          <span className="sm:hidden">OFFLINE</span>
          <HelpCircle className="w-3.5 h-3.5 opacity-80" />
        </div>
      );
    }

    if (captureState === 'ACTIVE') {
      return (
        <div
          onMouseEnter={() => setShowStatusTooltip(true)}
          onMouseLeave={() => setShowStatusTooltip(false)}
          className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#7DDB52]/15 border border-[#7DDB52]/40 text-[#7DDB52] text-xs font-mono font-bold cursor-help transition-all"
        >
          <span className="w-2 h-2 rounded-full bg-[#7DDB52] animate-pulse" />
          <span className="hidden sm:inline">PASSIVE CAPTURE ACTIVE</span>
          <span className="sm:hidden">ACTIVE</span>
          <HelpCircle className="w-3.5 h-3.5 opacity-80" />
        </div>
      );
    }

    return (
      <div
        onMouseEnter={() => setShowStatusTooltip(true)}
        onMouseLeave={() => setShowStatusTooltip(false)}
        className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#39D7FF]/10 border border-[#39D7FF]/30 text-[#39D7FF] text-xs font-mono font-bold cursor-help transition-all"
      >
        <span className="w-2 h-2 rounded-full bg-[#39D7FF]" />
        <span className="hidden sm:inline">SENSOR STANDBY</span>
        <span className="sm:hidden">STANDBY</span>
        <HelpCircle className="w-3.5 h-3.5 opacity-80" />
      </div>
    );
  };

  return (
    <header className="h-16 px-4 sm:px-6 bg-[#07072B]/95 backdrop-blur-md border-b border-[#242452] flex items-center justify-between shrink-0 z-20">
      {/* Left: Breadcrumbs & Page Title */}
      <div className="flex items-center gap-3 min-w-0">
        <div className="flex flex-col">
          <div className="flex items-center gap-1.5 text-[11px] font-mono text-[#A5A5BE]">
            {breadcrumbs.map((crumb, idx) => (
              <React.Fragment key={idx}>
                {idx > 0 && <span className="opacity-40">/</span>}
                <span className={idx === breadcrumbs.length - 1 ? 'text-[#39D7FF] font-semibold' : ''}>
                  {crumb}
                </span>
              </React.Fragment>
            ))}
          </div>
          <h1 className="text-base sm:text-lg font-heading font-extrabold text-[#F5F5F7] tracking-tight truncate">
            {pageTitle}
          </h1>
        </div>
      </div>

      {/* Center: Search Box if on a searchable page */}
      {onSearchChange !== undefined && (
        <div className="hidden md:flex items-center flex-1 max-w-xs mx-4">
          <div className="relative w-full">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-[#A5A5BE]" />
            <input
              type="text"
              value={searchQuery || ''}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Filter by IP, alert ID, flow..."
              className="w-full bg-[#10103D] border border-[#242452] rounded-xl pl-9 pr-4 py-1.5 text-xs font-mono text-[#F5F5F7] placeholder-[#A5A5BE]/60 focus:outline-none focus:border-[#39D7FF]/50 transition-colors"
            />
          </div>
        </div>
      )}

      {/* Right Controls & Real Sensor Indicator */}
      <div className="flex items-center gap-3">
        {/* Prominent Operational Sensor Status Badge */}
        <div className="relative">
          {renderStatusBadge()}

          {/* Tooltip */}
          {showStatusTooltip && (
            <div className="absolute right-0 top-full mt-2 w-72 p-3 bg-[#10103D] border border-[#242452] rounded-xl text-xs font-mono text-[#A5A5BE] shadow-2xl z-50 pointer-events-none">
              <span className="text-[#F5F5F7] font-bold block mb-1">
                {captureState === 'ACTIVE'
                  ? 'Passive Live Ingress Active'
                  : !backendAvailable
                  ? 'Backend Server Disconnected'
                  : 'Sensor in Standby Mode'}
              </span>
              <p className="text-[11px] font-sans leading-relaxed">
                {captureState === 'ACTIVE'
                  ? 'Npcap/Scapy passive background worker is actively monitoring packets. Extracted flows are streamed into trained ML detectors with zero packet payloads stored.'
                  : !backendAvailable
                  ? 'FastAPI server at localhost:8000 is unavailable. Check that the backend process is running.'
                  : 'Packet sniffer is currently idle. Select an interface and click "Start Monitoring" in the Live Monitor tab to begin live ingestion.'}
              </p>
            </div>
          )}
        </div>

        {/* Live UTC Clock */}
        <div className="hidden lg:flex items-center gap-1.5 px-3 py-1.5 rounded-xl bg-[#10103D] border border-[#242452] text-xs font-mono text-[#A5A5BE]">
          <Clock className="w-3.5 h-3.5 text-[#39D7FF]" />
          <span>{utcTime || 'UTC'}</span>
        </div>

        {/* Refresh API data button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            disabled={isRefreshing}
            className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#39D7FF] transition-all cursor-pointer disabled:opacity-50"
            title="Refresh live telemetry from backend API"
          >
            <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-[#39D7FF]' : ''}`} />
          </button>
        )}

        {/* Authenticated Operator Identity */}
        {user && (
          <div className="hidden md:flex items-center gap-2 px-2.5 py-1.5 rounded-xl bg-[#10103D] border border-[#242452] text-xs font-mono">
            <div className="w-5 h-5 rounded-md bg-[#07072B] border border-[#242452] flex items-center justify-center text-[#39D7FF]">
              <User className="w-3 h-3" />
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] font-semibold text-[#F5F5F7] max-w-[110px] truncate">
                {user.full_name || user.email}
              </span>
              <span className={`text-[9px] font-bold tracking-wider px-1.5 py-0.5 rounded font-mono ${
                user.role === 'admin'
                  ? 'bg-[#A8F500]/15 text-[#A8F500] border border-[#A8F500]/30'
                  : 'bg-[#39D7FF]/15 text-[#39D7FF] border border-[#39D7FF]/30'
              }`}>
                {user.role.toUpperCase()}
              </span>
            </div>
          </div>
        )}

        {/* Exit to Landing Page */}
        <button
          onClick={onExitToLanding}
          className="p-2 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all flex items-center gap-1.5 text-xs font-mono cursor-pointer"
          title="Return to Public Landing Page"
        >
          <ArrowLeft className="w-4 h-4" />
          <span className="hidden sm:inline">Landing Page</span>
        </button>

        {/* Sign Out Button */}
        <button
          onClick={handleLogout}
          className="p-2 rounded-lg bg-[#10103D] hover:bg-[#FF4D5A]/15 border border-[#242452] hover:border-[#FF4D5A]/40 text-[#A5A5BE] hover:text-[#FF4D5A] transition-all flex items-center gap-1.5 text-xs font-mono cursor-pointer"
          title="Sign out and invalidate session"
        >
          <LogOut className="w-4 h-4" />
          <span className="hidden sm:inline font-bold">Sign Out</span>
        </button>
      </div>
    </header>
  );
};
