import React, { useState, useEffect, useCallback, useRef } from 'react';
import { Sidebar } from './Sidebar';
import { TopBar } from './TopBar';
import { OverviewPage } from './OverviewPage';
import { LiveMonitorPage } from './LiveMonitorPage';
import { AlertsPage } from './AlertsPage';
import { FlowsPage } from './FlowsPage';
import { ModelsPage } from './ModelsPage';
import { ReportsPage } from './ReportsPage';
import { AlertDetailDrawer } from './AlertDetailDrawer';
import { FlowDetailModal } from './FlowDetailModal';
import { ErrorBoundary } from './ErrorBoundary';
import { detectionModelsData } from '../../data/modelsMetadata';
import {
  api,
  getApiBaseUrl,
  type DashboardOverviewResponse,
  type CaptureStatus
} from '../../services/api';
import type { ThreatAlert, NetworkFlow } from '../../types/telemetry';
import { AlertTriangle, RefreshCw, Compass } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';

interface DashboardContainerProps {
  onNavigate: (route: string) => void;
  currentRoute?: string;
}

interface ParsedDashboardRoute {
  tab: 'overview' | 'live-monitor' | 'alerts' | 'flows' | 'models' | 'reports' | 'not-found';
  alertId?: string;
  flowId?: string;
  isValid: boolean;
}

const parseDashboardRoute = (route: string): ParsedDashboardRoute => {
  const clean = route.replace(/\/+$/, '') || '/dashboard';

  if (clean === '/dashboard' || clean === '/dashboard/overview') {
    return { tab: 'overview', isValid: true };
  }
  if (clean === '/dashboard/live-monitor') {
    return { tab: 'live-monitor', isValid: true };
  }
  if (clean === '/dashboard/alerts') {
    return { tab: 'alerts', isValid: true };
  }
  if (clean.startsWith('/dashboard/alerts/')) {
    const alertId = decodeURIComponent(clean.slice('/dashboard/alerts/'.length));
    return { tab: 'alerts', alertId, isValid: true };
  }
  if (clean === '/dashboard/flows') {
    return { tab: 'flows', isValid: true };
  }
  if (clean.startsWith('/dashboard/flows/')) {
    const flowId = decodeURIComponent(clean.slice('/dashboard/flows/'.length));
    return { tab: 'flows', flowId, isValid: true };
  }
  if (clean === '/dashboard/models') {
    return { tab: 'models', isValid: true };
  }
  if (clean === '/dashboard/reports') {
    return { tab: 'reports', isValid: true };
  }

  return { tab: 'not-found', isValid: false };
};

export const DashboardContainer: React.FC<DashboardContainerProps> = ({
  onNavigate,
  currentRoute = '/dashboard'
}) => {
  const { logout } = useAuth();
  const initialParsed = parseDashboardRoute(currentRoute);
  const [currentTab, setCurrentTab] = useState<string>(initialParsed.tab);
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(false);

  // Real database and sensor state — zero mock records
  const [alerts, setAlerts] = useState<ThreatAlert[]>([]);
  const [flows, setFlows] = useState<NetworkFlow[]>([]);
  const [overview, setOverview] = useState<DashboardOverviewResponse | null>(null);
  const [captureStatus, setCaptureStatus] = useState<CaptureStatus | null>(null);

  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [backendAvailable, setBackendAvailable] = useState<boolean>(true);
  const [connectionError, setConnectionError] = useState<string | null>(null);

  // Alert inspection drawer state
  const [selectedAlert, setSelectedAlert] = useState<ThreatAlert | null>(null);
  const [isAlertDrawerOpen, setIsAlertDrawerOpen] = useState<boolean>(false);
  const [isAlertLoading, setIsAlertLoading] = useState<boolean>(false);
  const [alertDrawerError, setAlertDrawerError] = useState<string | null>(null);
  const [previousTabBeforeAlert, setPreviousTabBeforeAlert] = useState<string>('alerts');

  // Flow modal state
  const [selectedFlow, setSelectedFlow] = useState<NetworkFlow | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');

  const refreshTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const activeAlertReqRef = useRef<string | null>(null);

  // Fetch all real backend telemetry
  const loadTelemetry = useCallback(async (isSilent: boolean = false) => {
    if (!isSilent) setIsRefreshing(true);
    try {
      const [overviewData, flowListData, alertListData, capStatus] = await Promise.all([
        api.getDashboardOverview(),
        api.getFlows({ limit: 100 }),
        api.getAlerts({ limit: 100 }),
        api.getCaptureStatus()
      ]);

      setOverview(overviewData);
      setFlows(flowListData.flows || []);
      setAlerts(alertListData.alerts || []);
      setCaptureStatus(capStatus);
      setBackendAvailable(true);
      setConnectionError(null);
    } catch (err: any) {
      if (err?.status === 401) {
        // Session expired, revoked or invalid - clear auth and navigate to login
        await logout();
        onNavigate('/login');
        return;
      }
      setBackendAvailable(false);
      setConnectionError(err.message || 'Could not connect to backend API server.');
    } finally {
      setIsRefreshing(false);
    }
  }, [logout, onNavigate]);

  // Initial load on mount
  useEffect(() => {
    loadTelemetry(false);
  }, [loadTelemetry]);

  // Periodic polling to keep live data fresh
  useEffect(() => {
    refreshTimerRef.current = setInterval(() => {
      loadTelemetry(true);
    }, 4000);

    return () => {
      if (refreshTimerRef.current) {
        clearInterval(refreshTimerRef.current);
      }
    };
  }, [loadTelemetry]);

  // Fetch individual alert details safely
  const fetchAlertDetails = useCallback(async (alertId: string) => {
    activeAlertReqRef.current = alertId;
    setIsAlertDrawerOpen(true);
    setAlertDrawerError(null);

    // If already in list, set immediately for instant feedback
    const foundLocal = alerts.find(a => a.alert_id === alertId);
    if (foundLocal) {
      setSelectedAlert(foundLocal);
    }

    setIsAlertLoading(true);
    try {
      const fullAlert = await api.getAlertById(alertId);
      if (activeAlertReqRef.current === alertId) {
        setSelectedAlert(fullAlert);
        setAlertDrawerError(null);
      }
    } catch (err: any) {
      if (activeAlertReqRef.current === alertId) {
        if (!foundLocal) {
          setSelectedAlert(null);
        }
        setAlertDrawerError(err.message || `Alert "${alertId}" could not be retrieved from the server.`);
      }
    } finally {
      if (activeAlertReqRef.current === alertId) {
        setIsAlertLoading(false);
      }
    }
  }, [alerts]);

  // Synchronize route changes (browser Back/Forward, direct URL, in-app navigation)
  useEffect(() => {
    const parsed = parseDashboardRoute(currentRoute);
    if (parsed.tab !== 'not-found') {
      setCurrentTab(parsed.tab);
    } else {
      setCurrentTab('not-found');
    }

    if (parsed.alertId) {
      fetchAlertDetails(parsed.alertId);
    } else {
      setIsAlertDrawerOpen(false);
      setSelectedAlert(null);
      setAlertDrawerError(null);
      activeAlertReqRef.current = null;
    }

    if (parsed.flowId) {
      const localFlow = flows.find(f => f.flow_id === parsed.flowId);
      if (localFlow) {
        setSelectedFlow(localFlow);
      } else {
        api.getFlowById(parsed.flowId)
          .then(fl => setSelectedFlow(fl))
          .catch(() => {});
      }
    }
  }, [currentRoute, fetchAlertDetails, flows]);

  const handleSelectTab = (tab: string) => {
    setIsAlertDrawerOpen(false);
    setSelectedAlert(null);
    setAlertDrawerError(null);
    setSearchQuery('');

    let route = '/dashboard';
    if (tab === 'live-monitor') route = '/dashboard/live-monitor';
    else if (tab === 'alerts') route = '/dashboard/alerts';
    else if (tab === 'flows') route = '/dashboard/flows';
    else if (tab === 'models') route = '/dashboard/models';
    else if (tab === 'reports') route = '/dashboard/reports';

    onNavigate(route);
  };

  const handleExitToLanding = () => {
    onNavigate('/');
  };

  const handleAcknowledgeAlert = (alertId: string) => {
    setAlerts(prev => prev.map(a => {
      if (a.alert_id === alertId) {
        return { ...a, review_status: 'ACKNOWLEDGED' };
      }
      return a;
    }));
    if (selectedAlert && selectedAlert.alert_id === alertId) {
      setSelectedAlert(prev => prev ? { ...prev, review_status: 'ACKNOWLEDGED' } : null);
    }
  };

  const handleMarkReviewedAlert = (alertId: string) => {
    setAlerts(prev => prev.map(a => {
      if (a.alert_id === alertId) {
        return { ...a, review_status: 'REVIEWED', reviewed_at: Date.now() / 1000, reviewed_by: 'SOC-Analyst-Current' };
      }
      return a;
    }));
    if (selectedAlert && selectedAlert.alert_id === alertId) {
      setSelectedAlert(prev => prev ? {
        ...prev,
        review_status: 'REVIEWED',
        reviewed_at: Date.now() / 1000,
        reviewed_by: 'SOC-Analyst-Current'
      } : null);
    }
  };

  const handleSelectAlert = (alt: ThreatAlert) => {
    setPreviousTabBeforeAlert('alerts');
    setSelectedAlert(alt);
    setIsAlertDrawerOpen(true);
    setAlertDrawerError(null);
    onNavigate(`/dashboard/alerts/${encodeURIComponent(alt.alert_id)}`);
  };

  const handleSelectAlertById = (alertId: string, fromTab: string = 'live-monitor') => {
    setPreviousTabBeforeAlert(fromTab);
    onNavigate(`/dashboard/alerts/${encodeURIComponent(alertId)}`);
  };

  const handleCloseAlertDrawer = () => {
    setIsAlertDrawerOpen(false);
    setSelectedAlert(null);
    setAlertDrawerError(null);
    activeAlertReqRef.current = null;

    // Restore previous tab route smoothly
    const restoreRoute = previousTabBeforeAlert === 'live-monitor'
      ? '/dashboard/live-monitor'
      : '/dashboard/alerts';
    onNavigate(restoreRoute);
  };

  const handleViewFlowById = (flowId: string) => {
    const found = flows.find(f => f.flow_id === flowId);
    if (found) {
      setSelectedFlow(found);
    } else {
      api.getFlowById(flowId)
        .then(fl => setSelectedFlow(fl))
        .catch(() => {});
    }
  };

  const getPageInfo = () => {
    switch (currentTab) {
      case 'live-monitor':
        return { title: 'Live Ingress Telemetry', breadcrumbs: ['NETRA', 'Live Monitor'] };
      case 'alerts':
        return { title: 'Threat Alert Management', breadcrumbs: ['NETRA', 'Threat Alerts'] };
      case 'flows':
        return { title: 'Network Flow Explorer', breadcrumbs: ['NETRA', 'Network Flows'] };
      case 'models':
        return { title: 'Detection Components & Metrics', breadcrumbs: ['NETRA', 'Detection Models'] };
      case 'reports':
        return { title: 'Executive Reports & Analytics', breadcrumbs: ['NETRA', 'Reports & Analytics'] };
      case 'not-found':
        return { title: 'Navigation Notice', breadcrumbs: ['NETRA', 'Unknown Route'] };
      default:
        return { title: 'Operational Security Overview', breadcrumbs: ['NETRA', 'Overview'] };
    }
  };

  const pageInfo = getPageInfo();
  const unreviewedCount = alerts.filter(a => a.review_status === 'UNREVIEWED').length;

  return (
    <div className="min-h-screen bg-[#07072B] text-[#F5F5F7] flex flex-row overflow-hidden font-sans selection:bg-[#A8F500]/30 selection:text-[#F5F5F7]">
      {/* Collapsible Left Sidebar */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={handleSelectTab}
        onExitToLanding={handleExitToLanding}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
        alertCount={unreviewedCount}
        captureState={captureStatus?.state}
        activeInterface={captureStatus?.interface || undefined}
      />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col h-screen overflow-hidden min-w-0">
        {/* Slim Top Bar */}
        <TopBar
          pageTitle={pageInfo.title}
          breadcrumbs={pageInfo.breadcrumbs}
          searchQuery={currentTab === 'alerts' || currentTab === 'flows' ? searchQuery : undefined}
          onSearchChange={currentTab === 'alerts' || currentTab === 'flows' ? setSearchQuery : undefined}
          onRefresh={() => loadTelemetry(false)}
          onExitToLanding={handleExitToLanding}
          onLogout={async () => {
            await logout();
            onNavigate('/login');
          }}
          captureState={captureStatus?.state}
          backendAvailable={backendAvailable}
          isRefreshing={isRefreshing}
        />

        {/* Backend Disconnected Banner (If API fails) */}
        {!backendAvailable && (
          <div className="bg-[#FF4D5A]/15 border-b border-[#FF4D5A]/30 px-4 py-2.5 flex items-center justify-between text-xs font-mono text-[#FF4D5A] shrink-0">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 shrink-0" />
              <span>
                Backend unavailable. Could not connect to API server at {getApiBaseUrl()}.
                {connectionError ? ` (${connectionError})` : ''}
              </span>
            </div>
            <button
              onClick={() => loadTelemetry(false)}
              className="flex items-center gap-1.5 px-3 py-1 rounded bg-[#FF4D5A]/20 hover:bg-[#FF4D5A]/30 border border-[#FF4D5A]/40 text-[#F5F5F7] font-bold cursor-pointer transition-colors"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Connection</span>
            </button>
          </div>
        )}

        {/* Scrollable Page Body wrapped in ErrorBoundary */}
        <main className="flex-1 overflow-y-auto px-4 sm:px-6 lg:px-8 py-6">
          <ErrorBoundary
            fallbackTitle="Dashboard Content Error"
            onReset={() => loadTelemetry(false)}
            onNavigateHome={handleExitToLanding}
          >
            <div className="max-w-7xl mx-auto">
              {currentTab === 'overview' && (
                <OverviewPage
                  overview={overview}
                  recentAlerts={alerts}
                  flows={flows}
                  models={detectionModelsData}
                  onNavigateTab={handleSelectTab}
                  onSelectAlert={handleSelectAlert}
                />
              )}

              {currentTab === 'live-monitor' && (
                <LiveMonitorPage
                  onSelectAlertById={(aid) => handleSelectAlertById(aid, 'live-monitor')}
                  onRefreshParent={() => loadTelemetry(true)}
                />
              )}

              {currentTab === 'alerts' && (
                <AlertsPage
                  alerts={alerts}
                  onSelectAlert={handleSelectAlert}
                  onAcknowledgeAlert={handleAcknowledgeAlert}
                  onMarkReviewedAlert={handleMarkReviewedAlert}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                />
              )}

              {currentTab === 'flows' && (
                <FlowsPage
                  flows={flows}
                  onSelectFlow={(fl) => setSelectedFlow(fl)}
                  onNavigateToAlert={(altId) => handleSelectAlertById(altId, 'flows')}
                  searchQuery={searchQuery}
                  onSearchChange={setSearchQuery}
                />
              )}

              {currentTab === 'models' && (
                <ModelsPage
                  models={detectionModelsData}
                  liveStatuses={overview?.model_status}
                />
              )}

              {currentTab === 'reports' && (
                <ReportsPage
                  alerts={alerts}
                  models={detectionModelsData}
                  overview={overview}
                  flows={flows}
                />
              )}

              {currentTab === 'not-found' && (
                <div className="py-24 text-center font-mono space-y-4">
                  <div className="w-16 h-16 rounded-2xl bg-[#FF4D5A]/15 border border-[#FF4D5A]/30 flex items-center justify-center mx-auto text-[#FF4D5A]">
                    <Compass className="w-8 h-8" />
                  </div>
                  <div className="space-y-1">
                    <h2 className="text-xl font-heading font-extrabold text-[#F5F5F7]">
                      Dashboard Route Not Found
                    </h2>
                    <p className="text-xs text-[#A5A5BE] max-w-md mx-auto font-mono">
                      The route <code className="text-[#39D7FF]">{currentRoute}</code> does not match any active telemetry section.
                    </p>
                  </div>
                  <div className="pt-2">
                    <button
                      onClick={() => handleSelectTab('overview')}
                      className="px-4 py-2.5 rounded-xl bg-[#39D7FF]/20 hover:bg-[#39D7FF]/30 border border-[#39D7FF]/40 text-[#F5F5F7] text-xs font-bold transition-all cursor-pointer inline-flex items-center gap-2"
                    >
                      <span>Return to Operational Overview</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          </ErrorBoundary>
        </main>
      </div>

      {/* Alert Detail Side Panel Drawer */}
      <AlertDetailDrawer
        alert={selectedAlert}
        isOpen={isAlertDrawerOpen}
        isLoading={isAlertLoading}
        error={alertDrawerError}
        onRetry={() => {
          const parsed = parseDashboardRoute(currentRoute);
          if (parsed.alertId) {
            fetchAlertDetails(parsed.alertId);
          } else if (selectedAlert?.alert_id) {
            fetchAlertDetails(selectedAlert.alert_id);
          }
        }}
        onClose={handleCloseAlertDrawer}
        onAcknowledge={handleAcknowledgeAlert}
        onMarkReviewed={handleMarkReviewedAlert}
        onViewFlow={handleViewFlowById}
      />

      {/* Flow Detail Modal Dialog */}
      <FlowDetailModal
        flow={selectedFlow}
        onClose={() => setSelectedFlow(null)}
        onNavigateToAlert={(alertId) => {
          setSelectedFlow(null);
          handleSelectAlertById(alertId, 'flows');
        }}
      />
    </div>
  );
};
