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
  ips?: string[];
  mac?: string;
  is_active: boolean;
  is_wireless?: boolean;
  is_loopback?: boolean;
}

export interface CaptureStatus {
  state: 'ACTIVE' | 'STOPPED' | 'ERROR' | 'STANDBY';
  status?: string;
  diagnostic_state?: 'SENSOR_NOT_INSTALLED' | 'SENSOR_OFFLINE' | 'PERMISSION_REQUIRED' | 'INTERFACE_UNAVAILABLE' | 'RUNNING_NO_PACKETS' | 'ACTIVE' | 'STANDBY' | 'OCCUPIED_BY_ANOTHER_USER' | 'ERROR';
  sensor_installed?: boolean;
  is_owner?: boolean;
  busy_by_other_user?: boolean;
  is_local_client?: boolean;
  message?: string;
  interface: string | null;
  configured_interface?: string | null;
  packets_captured: number;
  packets_dropped: number;
  flows_created: number;
  threats_detected: number;
  last_packet_time: number | null;
  current_pps: number;
  current_kbps: number;
  error_message: string | null;
  uptime_seconds?: number;
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
  sensor_id?: string;
  source?: string;
}

async function request<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const baseUrl = getApiBaseUrl();
  const url = `${baseUrl}${endpoint}`;
  const token = typeof localStorage !== 'undefined' ? localStorage.getItem('threattrack_token') : null;
  try {
    const response = await fetch(url, {
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
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

  /** Register a new user account */
  async register(data: { full_name: string; email: string; password: string }): Promise<LoginResponse> {
    const res = await request<LoginResponse>('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    if (res.token && typeof localStorage !== 'undefined') {
      localStorage.setItem('threattrack_token', res.token);
    }
    return res;
  },

  /** Authenticate operator credentials */
  async login(credentials: { email: string; password: string }): Promise<LoginResponse> {
    const res = await request<LoginResponse>('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    if (res.token && typeof localStorage !== 'undefined') {
      localStorage.setItem('threattrack_token', res.token);
    }
    return res;
  },

  /** Terminate operator session */
  async logout(): Promise<{ success: boolean; message: string }> {
    if (typeof localStorage !== 'undefined') {
      localStorage.removeItem('threattrack_token');
    }
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
    const token = typeof localStorage !== 'undefined' ? localStorage.getItem('threattrack_token') : null;
    const response = await fetch(url, {
      method: 'GET',
      credentials: 'include',
      headers: {
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
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
      filename = `ThreatTrack_${prefix}_${timestamp}.${ext}`;
    }

    // Ensure filesystem-safe filename
    filename = filename.replace(/[/\\?%*:|"<>]/g, '_');

    const blob = await response.blob();
    return { filename, blob };
  },

  /** Retrieve all enrolled remote sensor devices */
  async getEnrolledSensors(status?: string): Promise<EnrolledSensor[]> {
    return request(`/api/sensor/list${status ? `?status=${encodeURIComponent(status)}` : ''}`);
  },

  /** Enroll a new remote Windows sensor device */
  async enrollSensor(payload: { sensor_id: string; name: string }): Promise<{
    success: boolean;
    message: string;
    sensor: EnrolledSensor;
    api_key: string;
  }> {
    return request('/api/sensor/enroll', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
  },

  /** Revoke an enrolled sensor credential */
  async revokeSensor(sensor_id: string): Promise<{ success: boolean; message: string }> {
    return request('/api/sensor/revoke', {
      method: 'POST',
      body: JSON.stringify({ sensor_id }),
    });
  },

  /** Retrieve live stream events observed by enrolled remote sensors */
  async getRemoteSensorEvents(sensor_id?: string, limit: number = 30): Promise<LiveStreamEventItem[]> {
    const query = new URLSearchParams();
    if (sensor_id) query.set('sensor_id', sensor_id);
    query.set('limit', String(limit));
    return request(`/api/sensor/events?${query.toString()}`);
  },

  /** Control remote sensor packet capture (START or STOP) */
  async controlSensor(
    sensor_id: string,
    command: 'START' | 'STOP',
    interfaceName?: string
  ): Promise<{
    success: boolean;
    message: string;
    sensor_id: string;
    command: string;
    target_state: string;
    actual_state: string;
  }> {
    return request(`/api/sensor/${encodeURIComponent(sensor_id)}/control`, {
      method: 'POST',
      body: JSON.stringify({ command, interface: interfaceName || null }),
    });
  },

  /** Download self-contained Windows sensor agent distribution ZIP */
  async downloadWindowsSensor(sensorId?: string, apiKey?: string): Promise<{ blob: Blob; filename: string }> {
    const params = new URLSearchParams();
    if (sensorId) params.append('sensor_id', sensorId);
    if (apiKey) params.append('api_key', apiKey);
    const qs = params.toString() ? `?${params.toString()}` : '';

    const baseUrl = getApiBaseUrl();
    const token = typeof localStorage !== 'undefined' ? localStorage.getItem('threattrack_token') : null;
    const res = await fetch(`${baseUrl}/api/sensor/download/windows-agent${qs}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
      },
    });

    if (!res.ok) {
      let errDetail = 'Failed to download sensor package';
      try {
        const json = await res.json();
        errDetail = json.detail || errDetail;
      } catch {}
      throw new Error(errDetail);
    }

    const blob = await res.blob();
    const disposition = res.headers.get('Content-Disposition');
    let filename = sensorId ? `ThreatTrack-Sensor-${sensorId}.zip` : 'ThreatTrack-Windows-Sensor.zip';
    if (disposition && disposition.includes('filename=')) {
      const match = disposition.match(/filename="?([^"]+)"?/);
      if (match && match[1]) filename = match[1];
    }
    return { blob, filename };
  },
};

export interface EnrolledSensor {
  id: number;
  sensor_id: string;
  name: string;
  api_key_prefix: string;
  owner_email: string;
  status: 'ACTIVE' | 'REVOKED';
  target_state?: 'RUNNING' | 'STOPPED';
  actual_state?: string;
  target_interface?: string | null;
  last_seen_at: string | null;
  last_ip: string | null;
  sensor_version: string | null;
  hostname: string | null;
  packets_uploaded: number;
  flows_uploaded: number;
  alerts_uploaded: number;
  created_at: string | null;
  revoked_at?: string | null;
}

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
  token?: string;
}

export interface CurrentUserResponse {
  user: UserProfile;
}
