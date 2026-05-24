import type {
  Alert, AttackTypeBreakdown, DetectionStatus, HealthResponse,
  NetworkInterface, PcapJob, Report, SavedReport, SeverityBreakdown,
  Thresholds, TimelinePoint, TokenResponse, TopAttacker, UserInfo, UserRecord,
} from '../types';

const BASE = '/api/v1';

function getToken(): string | null {
  return localStorage.getItem('vs_token');
}

function authHeaders(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...authHeaders(),
      ...(init.headers as Record<string, string> | undefined),
    },
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail ?? res.statusText);
  }
  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  readonly status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

// Auth
export const login = (username: string, password: string) =>
  request<TokenResponse>('/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username, password }),
  });

export const getMe = () => request<UserInfo>('/auth/me');

export const registerUser = (username: string, password: string, roles: string[]) =>
  request<UserInfo>('/auth/register', {
    method: 'POST',
    body: JSON.stringify({ username, password, roles }),
  });

// Health
export const getHealth = () => request<HealthResponse>('/health');

// Alerts
export const getAlerts = (limit = 200) =>
  request<Alert[]>(`/alerts?limit=${limit}`);

// Reports
export const generateReport = () =>
  request<Report>('/reports/generate', { method: 'POST' });

// Admin
export const importFlows = (limit = 1000) =>
  request<{ imported: number; counts: HealthResponse['counts'] }>(
    `/admin/import-flows?limit=${limit}`,
    { method: 'POST' },
  );

export const ingestAlert = (alert: Omit<Alert, never>) =>
  request<{ stored: boolean }>('/alerts', {
    method: 'POST',
    body: JSON.stringify(alert),
  });

// Detection
export const getDetectionStatus = () =>
  request<DetectionStatus>('/detection/status');

export const startDetection = (iface?: string) =>
  request<DetectionStatus>(
    `/detection/start${iface ? `?interface=${encodeURIComponent(iface)}` : ''}`,
    { method: 'POST' },
  );

export const stopDetection = () =>
  request<DetectionStatus>('/detection/stop', { method: 'POST' });

export const getInterfaces = () =>
  request<NetworkInterface[]>('/detection/interfaces');

export const reclassifyAttacks = () =>
  request<{ reclassified: number }>('/admin/reclassify-attacks', { method: 'POST' });

// Analytics
export const getTimeline = (hours = 24) =>
  request<TimelinePoint[]>(`/analytics/timeline?hours=${hours}`);

export const getTopAttackers = (limit = 10) =>
  request<TopAttacker[]>(`/analytics/top-attackers?limit=${limit}`);

export const getAttackTypes = () =>
  request<AttackTypeBreakdown[]>('/analytics/attack-types');

export const getSeverityBreakdown = () =>
  request<SeverityBreakdown[]>('/analytics/severity-breakdown');

// Thresholds
export const getThresholds = () =>
  request<Thresholds>('/admin/thresholds');

export const setThresholds = (body: Partial<Thresholds>) =>
  request<Thresholds>('/admin/thresholds', {
    method: 'PUT',
    body: JSON.stringify(body),
  });

// PCAP upload
export const uploadPcap = async (file: File): Promise<PcapJob> => {
  const token = localStorage.getItem('vs_token');
  const form = new FormData();
  form.append('file', file);
  const res = await fetch('/api/v1/upload/pcap', {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: form,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new ApiError(res.status, body.detail ?? res.statusText);
  }
  return res.json();
};

export const getPcapJob = (jobId: string) =>
  request<PcapJob>(`/upload/pcap/${jobId}`);

// Report history
export const getReportHistory = (limit = 50) =>
  request<SavedReport[]>(`/reports/history?limit=${limit}`);

export const deleteReport = (id: number) =>
  request<{ deleted: boolean }>(`/reports/${id}`, { method: 'DELETE' });

export const downloadReport = async (id: number): Promise<void> => {
  const token = localStorage.getItem('vs_token');
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const r = await fetch(`/api/v1/reports/${id}/download`, { headers });
  if (!r.ok) throw new Error(`Download failed: ${r.status} ${r.statusText}`);
  const blob = await r.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `vulnsight_report_${id}.json`;
  a.click();
  URL.revokeObjectURL(url);
};

// Alert cleanup / retention
export const previewCleanup = (days: number) =>
  request<{ count: number; older_than_days: number }>(`/admin/cleanup/preview?older_than_days=${days}`);

export const runCleanup = (days: number) =>
  request<{ deleted: number; older_than_days: number }>(
    `/admin/cleanup?older_than_days=${days}`,
    { method: 'POST' },
  );

export const runCleanupAll = () =>
  request<{ deleted: number }>('/admin/cleanup/all', { method: 'POST' });

// User management
export const listUsers = () => request<UserRecord[]>('/admin/users');

export const toggleUserActive = (id: number, is_active: boolean) =>
  request<UserRecord>(`/admin/users/${id}/active`, {
    method: 'PUT',
    body: JSON.stringify({ is_active }),
  });

export const deleteUser = (id: number) =>
  request<{ deleted: boolean }>(`/admin/users/${id}`, { method: 'DELETE' });

export const updateUserRoles = (id: number, roles: string[]) =>
  request<UserRecord>(`/admin/users/${id}/roles`, {
    method: 'PUT',
    body: JSON.stringify({ roles }),
  });

// CSV export (triggers browser download)
export async function downloadCsv(limit = 5000): Promise<void> {
  const token = localStorage.getItem('vs_token');
  const url = `/api/v1/reports/export/csv?limit=${limit}`;
  const headers: Record<string, string> = {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const r = await fetch(url, { headers });
  if (!r.ok) throw new Error(`CSV export failed: ${r.status} ${r.statusText}`);
  const blob = await r.blob();
  const blobUrl = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = blobUrl;
  a.download = `vulnsight_alerts_${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  URL.revokeObjectURL(blobUrl);
}
