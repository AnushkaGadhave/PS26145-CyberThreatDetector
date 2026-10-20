import React from 'react';
import {
  LayoutDashboard,
  Radio,
  ShieldAlert,
  Network,
  Cpu,
  BarChart3,
  ArrowLeft,
  ChevronLeft,
  ChevronRight,
  LogOut,
  User
} from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface SidebarProps {
  currentTab: string;
  onSelectTab: (tab: string) => void;
  onExitToLanding: () => void;
  collapsed: boolean;
  onToggleCollapse: () => void;
  alertCount: number;
  captureState?: string;
  activeInterface?: string;
}

export const Sidebar: React.FC<SidebarProps> = ({
  currentTab,
  onSelectTab,
  onExitToLanding,
  collapsed,
  onToggleCollapse,
  alertCount,
  captureState = 'STOPPED',
  activeInterface = 'Wi-Fi 3'
}) => {
  const { user, logout } = useAuth();
  const navItems = [
    {
      id: 'overview',
      label: 'Dashboard Overview',
      shortLabel: 'Overview',
      icon: LayoutDashboard,
      route: '/dashboard'
    },
    {
      id: 'live-monitor',
      label: 'Live Monitor',
      shortLabel: 'Monitor',
      icon: Radio,
      route: '/dashboard/live-monitor',
      pulse: true
    },
    {
      id: 'alerts',
      label: 'Threat Alerts',
      shortLabel: 'Alerts',
      icon: ShieldAlert,
      route: '/dashboard/alerts',
      badge: alertCount > 0 ? alertCount : undefined
    },
    {
      id: 'flows',
      label: 'Network Flows',
      shortLabel: 'Flows',
      icon: Network,
      route: '/dashboard/flows'
    },
    {
      id: 'models',
      label: 'Detection Models',
      shortLabel: 'Models',
      icon: Cpu,
      route: '/dashboard/models'
    },
    {
      id: 'reports',
      label: 'Reports & Analytics',
      shortLabel: 'Reports',
      icon: BarChart3,
      route: '/dashboard/reports'
    }
  ];

  return (
    <aside
      className={`bg-[#07072B] border-r border-[#242452] flex flex-col justify-between transition-all duration-300 z-30 shrink-0 ${
        collapsed ? 'w-20' : 'w-64'
      }`}
    >
      {/* Top Branding Section */}
      <div>
        <div className="h-16 px-4 flex items-center justify-between border-b border-[#242452]">
          <div className="flex items-center gap-3 overflow-hidden">
            <div className="w-9 h-9 rounded-xl bg-[#10103D] border border-[#242452] flex items-center justify-center shrink-0">
              <div className="w-2.5 h-2.5 rounded-full bg-[#A8F500] animate-pulse" />
            </div>
            {!collapsed && (
              <div className="flex flex-col">
                <span className="font-heading font-extrabold text-base tracking-tight text-[#F5F5F7] flex items-center gap-1.5">
                  NETRA
                  <span className="w-1.5 h-1.5 rounded-full bg-[#A8F500]" />
                </span>
                <span className="text-[10px] font-mono text-[#A5A5BE]">
                  PS 26145 Console
                </span>
              </div>
            )}
          </div>

          <button
            onClick={onToggleCollapse}
            className="p-1.5 rounded-lg bg-[#10103D] hover:bg-[#15154A] border border-[#242452] text-[#A5A5BE] hover:text-[#F5F5F7] transition-all cursor-pointer"
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          >
            {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
          </button>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1.5 mt-2">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentTab === item.id;

            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-mono transition-all group cursor-pointer ${
                  isActive
                    ? 'bg-[#A8F500] text-[#07072B] font-bold shadow-md shadow-[#A8F500]/15'
                    : 'text-[#A5A5BE] hover:text-[#F5F5F7] hover:bg-[#10103D]'
                }`}
                title={collapsed ? item.label : undefined}
              >
                <div className="relative shrink-0 flex items-center justify-center">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-[#07072B]' : 'text-[#A5A5BE] group-hover:text-[#F5F5F7]'}`} />
                  {item.pulse && (
                    <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-[#39D7FF] animate-ping" />
                  )}
                </div>

                {!collapsed && (
                  <span className="truncate flex-grow text-left">
                    {item.label}
                  </span>
                )}

                {!collapsed && item.badge !== undefined && (
                  <span
                    className={`text-[10px] px-1.5 py-0.5 rounded-full font-mono font-bold shrink-0 ${
                      isActive
                        ? 'bg-[#07072B] text-[#A8F500]'
                        : 'bg-[#FF4D5A]/20 text-[#FF4D5A] border border-[#FF4D5A]/40'
                    }`}
                  >
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Info & Exit */}
      <div className="p-3 border-t border-[#242452] space-y-2">
        {!collapsed && (
          <div className="p-3 rounded-xl bg-[#10103D]/60 border border-[#242452] space-y-1.5 text-[11px] font-mono">
            <div className={`flex items-center justify-between ${captureState === 'ACTIVE' ? 'text-[#7DDB52]' : 'text-[#39D7FF]'}`}>
              <span className="flex items-center gap-1.5 font-bold">
                <span className={`w-1.5 h-1.5 rounded-full ${captureState === 'ACTIVE' ? 'bg-[#7DDB52] animate-pulse' : 'bg-[#39D7FF]'}`} />
                {captureState === 'ACTIVE' ? 'CAPTURE ACTIVE' : 'SENSOR STANDBY'}
              </span>
              <span className="text-[#A5A5BE] text-[10px] truncate max-w-[85px]" title={activeInterface}>
                {activeInterface}
              </span>
            </div>
            <p className="text-[10px] text-[#A5A5BE] leading-relaxed">
              Passive Unidirectional RX • Zero-Transmit Enforced
            </p>
          </div>
        )}

        {/* Operator Profile Card (Expanded) */}
        {!collapsed && user && (
          <div className="p-2.5 rounded-xl bg-[#10103D] border border-[#242452] flex items-center justify-between">
            <div className="flex items-center gap-2 overflow-hidden">
              <div className="w-7 h-7 rounded-lg bg-[#07072B] border border-[#242452] flex items-center justify-center text-[#39D7FF] shrink-0">
                <User className="w-3.5 h-3.5" />
              </div>
              <div className="flex flex-col overflow-hidden text-left">
                <span className="text-xs font-semibold text-[#F5F5F7] truncate font-mono">
                  {user.full_name || user.email}
                </span>
                <span className={`text-[9px] font-bold tracking-wider uppercase font-mono ${
                  user.role === 'admin' ? 'text-[#A8F500]' : 'text-[#39D7FF]'
                }`}>
                  {user.role} OPERATOR
                </span>
              </div>
            </div>
            <button
              onClick={async () => {
                await logout();
                onExitToLanding();
              }}
              className="p-1.5 rounded-lg text-[#A5A5BE] hover:text-[#FF4D5A] hover:bg-[#FF4D5A]/15 border border-transparent hover:border-[#FF4D5A]/30 transition-all cursor-pointer"
              title="Sign Out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}

        {/* Operator Sign Out Button (Collapsed) */}
        {collapsed && user && (
          <button
            onClick={async () => {
              await logout();
              onExitToLanding();
            }}
            className="w-full flex items-center justify-center p-2 rounded-xl text-[#A5A5BE] hover:text-[#FF4D5A] hover:bg-[#FF4D5A]/15 border border-transparent hover:border-[#FF4D5A]/30 transition-all cursor-pointer"
            title={`Sign Out (${user.full_name || user.email})`}
          >
            <LogOut className="w-4 h-4" />
          </button>
        )}

        <button
          onClick={onExitToLanding}
          className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-mono text-[#A5A5BE] hover:text-[#F5F5F7] hover:bg-[#10103D] border border-transparent hover:border-[#242452] transition-all cursor-pointer ${
            collapsed ? 'justify-center' : ''
          }`}
          title={collapsed ? "Back to Landing Page" : undefined}
        >
          <ArrowLeft className="w-4 h-4 shrink-0" />
          {!collapsed && <span>Back to Landing Page</span>}
        </button>
      </div>
    </aside>
  );
};
