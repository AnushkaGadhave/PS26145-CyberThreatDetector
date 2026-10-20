/**
 * SIH Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
 * Module: frontend/src/services/api.ts
 *
 * Real API client layer communicating with the FastAPI backend.
 * All data is strictly fetched from actual backend endpoints.
 * No mock data, no synthetic fallbacks.
 */

export function getApiBaseUrl(): string {
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL;
  }
  if (typeof window !== 'undefined' && window.location) {
    // Align host dynamically (localhost vs 127.0.0.1) so HttpOnly session cookies are strictly Same-Site
    const hostname = window.location.hostname || 'localhost';
    const protocol = window.location.protocol || 'http:';
    return `${protocol}//${hostname}:8000`;
  }
  return 'http://127.0.0.1:8000';
}

export const API_BASE_URL = getApiBaseUrl();

export interface ApiError {
  message: string;
  status?: number;
}

export interface CaptureInterface {
  name: string;
  description: string;
  ip: string;
  mac: string;
  is_active: boolean;
}

export interface CaptureStatus {
  state: 'ACTIVE' | 'STOPPED' | 'ERROR';
  interface: string | null;
  packets_captured: number;
  packets_dropped: number;
  flows_created: number;
  threats_detected: number;
  last_packet_time: number | null;
  current_pps: number;
  current_kbps: number;
  error_message: string | null;
}

export interface FlowListResponse {
  total: number;
  limit: number;
  offset: number;
  flows: any[];
}

export interface AlertListResponse {
  total: number;
  limit: number;
  offset: number;
  alerts: any[];
}

export interface AlertSummaryResponse {
  total_alerts: number;
  total_flows: number;
  benign_count: number;
  low_count: number;
  medium_count: number;
  high_count: number;
  critical_count: number;
  ddos_count: number;
  botnet_c2_count: number;
  recon_portscan_count: number;
  multi_threat_count: number;
  unlabeled_live_alerts: number;
}

export interface ModelStatusResponse {
  id?: number;
  model_name: string;
  status: string;
  compatible: string;
  reason: string;
  updated_at?: string;
}

export interface TopIPItem {
  ip: string;
  count: number;
}

export interface DashboardOverviewResponse {
  total_flows: number;
  total_alerts: number;
  alerts_last_5_minutes: number;
  alerts_last_15_minutes: number;
  alerts_last_24_hours: number;
  severity_counts: Record<string, number>;
  threat_counts: Record<string, number>;
  top_source_ips: TopIPItem[];
  top_destination_ips: TopIPItem[];
  protocol_counts: Record<string, number>;
  model_status: ModelStatusResponse[];
}

export interface LiveStreamEventItem {
  id: string;
  timestamp: number;
  flow_id: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  protocol: string;
  packets: number;
  bytes: number;
  threat_outcome: string;
  severity: string;
  alert_id?: string;
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${endpoint}`;
  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!response.ok) {
      let errorMsg = `Server error: ${response.status} ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorMsg = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        }
      } catch {
        // use default errorMsg
      }
      const err = new Error(errorMsg) as Error & { status: number };
      err.status = response.status;
      throw err;
    }

    return await response.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      const connErr = new Error('Backend unavailable. Could not connect to API server at ' + baseUrl) as Error & { status: number };
      connErr.status = 0;
      throw connErr;
    }
    throw err;
  }
}

export const api = {
  /** Check backend health */
  async checkHealth(): Promise<{ status: string; service: string }> {
    return request('/health');
  },

  /** Get complete dashboard overview snapshot */
  async getDashboardOverview(): Promise<DashboardOverviewResponse> {
    return request('/api/dashboard/overview');
  },

  /** Get paginated network flows */
  async getFlows(params?: {
    limit?: number;
    offset?: number;
    protocol?: string;
    src_ip?: string;
    dst_ip?: string;
    traffic_context?: string;
  }): Promise<FlowListResponse> {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset !== undefined) query.append('offset', params.offset.toString());
    if (params?.protocol) query.append('protocol', params.protocol);
    if (params?.src_ip) query.append('src_ip', params.src_ip);
    if (params?.dst_ip) query.append('dst_ip', params.dst_ip);
    if (params?.traffic_context) query.append('traffic_context', params.traffic_context);

    const queryString = query.toString();
    return request(`/api/flows${queryString ? `?${queryString}` : ''}`);
  },

  /** Get single flow by ID */
  async getFlowById(flowId: string): Promise<any> {
    return request(`/api/flows/${encodeURIComponent(flowId)}`);
  },

  /** Get paginated threat alerts */
  async getAlerts(params?: {
    limit?: number;
    offset?: number;
    severity?: string;
    threat_class?: string;
    detector?: string;
    traffic_context?: string;
    start_time?: number;
    end_time?: number;
  }): Promise<AlertListResponse> {
    const query = new URLSearchParams();
    if (params?.limit) query.append('limit', params.limit.toString());
    if (params?.offset !== undefined) query.append('offset', params.offset.toString());
    if (params?.severity) query.append('severity', params.severity);
    if (params?.threat_class) query.append('threat_class', params.threat_class);
    if (params?.detector) query.append('detector', params.detector);
    if (params?.traffic_context) query.append('traffic_context', params.traffic_context);
    if (params?.start_time) query.append('start_time', params.start_time.toString());
    if (params?.end_time) query.append('end_time', params.end_time.toString());

    const queryString = query.toString();
    return request(`/api/alerts${queryString ? `?${queryString}` : ''}`);
  },

  /** Get recent alerts for dashboard live polling */
  async getRecentAlerts(limit: number = 20): Promise<any[]> {
    return request(`/api/alerts/recent?limit=${limit}`);
  },

  /** Get aggregated alert summary */
  async getAlertSummary(): Promise<AlertSummaryResponse> {
    return request('/api/alerts/summary');
  },

  /** Get single alert by ID */
  async getAlertById(alertId: string): Promise<any> {
    return request(`/api/alerts/${encodeURIComponent(alertId)}`);
  },

  /** Get model operational and compatibility statuses */
  async getModelStatuses(): Promise<ModelStatusResponse[]> {
    return request('/api/models/status');
  },

  /** Get live capture status and metrics */
  async getCaptureStatus(): Promise<CaptureStatus> {
    return request('/api/capture/status');
  },

  /** Get host network interfaces */
  async getCaptureInterfaces(): Promise<CaptureInterface[]> {
    return request('/api/capture/interfaces');
  },

  /** Start live passive capture on interface */
  async startCapture(interfaceName?: string): Promise<{ success: boolean; message: string; interface?: string }> {
    return request('/api/capture/start', {
      method: 'POST',
      body: JSON.stringify({ interface: interfaceName || null }),
    });
  },

  /** Stop live passive capture */
  async stopCapture(): Promise<{ success: boolean; message: string; packets_captured?: number; flows_created?: number; alerts_generated?: number }> {
    return request('/api/capture/stop', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  },

  /** Stream recent live events */
  async getRecentLiveEvents(limit: number = 30): Promise<LiveStreamEventItem[]> {
    return request(`/api/capture/events?limit=${limit}`);
  },

  /** Authenticate operator credentials */
  async login(credentials: { email: string; password: string }): Promise<LoginResponse> {
    return request('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
  },

  /** Terminate operator session */
  async logout(): Promise<{ success: boolean; message: string }> {
    return request('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify({}),
    });
  },

  /** Retrieve currently signed in operator */
  async getCurrentUser(): Promise<CurrentUserResponse> {
    return request('/api/auth/me');
  },

  /** Download backend-generated report file with real Content-Disposition filename */
  async downloadReport(params: {
    reportType?: 'comprehensive' | 'alerts' | 'flows' | 'models';
    format?: 'csv' | 'json';
    severity?: string;
    threatClass?: string;
    limit?: number;
  }): Promise<{ filename: string; blob: Blob }> {
    const q = new URLSearchParams();
    if (params.reportType) q.set('report_type', params.reportType);
    if (params.format) q.set('format', params.format);
    if (params.severity) q.set('severity', params.severity);
    if (params.threatClass) q.set('threat_class', params.threatClass);
    if (params.limit) q.set('limit', String(params.limit));

    const baseUrl = getApiBaseUrl();
    const url = `${baseUrl}/api/reports/export?${q.toString()}`;
    const response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
    });

    if (!response.ok) {
      let errorMsg = `Report generation failed: ${response.status} ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorMsg = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        }
      } catch {
        // use default
      }
      const err = new Error(errorMsg) as Error & { status: number };
      err.status = response.status;
      throw err;
    }

    // Extract filename from Content-Disposition header if present (supporting RFC 6266 / RFC 5987)
    const disposition = response.headers.get('Content-Disposition') || '';
    let filename = '';
    const utf8Match = disposition.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf8Match && utf8Match[1]) {
      try {
        filename = decodeURIComponent(utf8Match[1].trim());
      } catch {
        filename = utf8Match[1].trim();
      }
    } else {
      const match = disposition.match(/filename=["']?([^"';]+)["']?/i);
      if (match && match[1]) {
        filename = match[1].trim();
      }
    }

    if (!filename) {
      const now = new Date();
      const pad = (n: number) => n.toString().padStart(2, '0');
      const timestamp = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
      const ext = params.format === 'json' ? 'json' : 'csv';
      const prefixMap: Record<string, string> = {
        comprehensive: 'Security_Report',
        alerts: 'Threat_Report',
        flows: 'Flows_Report',
        models: 'Model_Audit'
      };
      const prefix = prefixMap[params.reportType || 'comprehensive'] || 'Security_Report';
      filename = `NETRA_${prefix}_${timestamp}.${ext}`;
    }

    // Ensure filesystem-safe filename
    filename = filename.replace(/[/\\?%*:|"<>]/g, '_');

    const blob = await response.blob();
    return { filename, blob };
  },
};

export interface UserProfile {
  user_id: string;
  email: string;
  full_name: string;
  role: 'admin' | 'analyst' | 'viewer' | string;
  is_active: boolean;
  last_login_at?: string | null;
  created_at?: string | null;
}

export interface LoginResponse {
  success: boolean;
  message: string;
  user: UserProfile;
}

export interface CurrentUserResponse {
  user: UserProfile;
}
