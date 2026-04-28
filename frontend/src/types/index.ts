export interface ShapInsight {
  feature: string;
  impact: number;
  direction: string;
}

export interface Alert {
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  protocol: number | null;
  interface: string | null;
  prediction: number;
  label: string;
  confidence: number;
  confidence_level: string;
  severity: string;
  triage_action: string;
  is_malicious: boolean;
  attack_type?: string | null;
  dedup_count?: number;
  shap_top_features: ShapInsight[];
  sensor_id?: string | null;
}

export interface Report {
  generated_at: string;
  total_events: number;
  malicious_events: number;
  benign_events: number;
  malicious_ratio: number;
  severity_breakdown: Record<string, number>;
  top_targets: Record<string, number>;
}

export interface HealthResponse {
  status: string;
  timestamp: string;
  database_path: string;
  counts: {
    alerts: number;
    flow: number;
    packet: number;
    pcap_file: number;
  };
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_at: string;
}

export interface UserInfo {
  id: number;
  username: string;
  roles: string[];
}

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'warning';

export interface DetectionStatus {
  running: boolean;
  interface: string | null;
  flows_processed: number;
  predictions_made: number;
  malicious_detected: number;
  last_flow_at: string | null;
  last_alert_at: string | null;
  error: string | null;
  started_at: string | null;
}

export interface TimelinePoint {
  bucket: string;   // "2024-06-01 12:00"
  count: number;
  malicious: number;
}

export interface TopAttacker {
  source_ip: string;
  total: number;
  malicious: number;
  event_count: number;
}

export interface AttackTypeBreakdown {
  attack_type: string;
  count: number;
  event_count: number;
}

export interface SeverityBreakdown {
  severity: string;
  count: number;
  event_count: number;
}

export interface Thresholds {
  malicious_confidence_min: number;
  dedup_window_seconds: number;
  alert_notification_severities: string[];
  max_alerts_per_page: number;
}

export interface SavedReport {
  id: number;
  name: string;
  type: string;
  period: string;
  alert_count: number;
  generated_at: string;
  report_size: number;
}

export interface UserRecord {
  id: number;
  username: string;
  is_active: boolean;
  created_at: string;
  roles: string[];
}

export interface SensorKey {
  id: number;
  name: string;
  key_prefix: string;
  is_active: boolean;
  created_at: string;
  last_seen_at: string | null;
  alerts_sent: number;
  /** Only present immediately after creation — never returned again */
  raw_key?: string;
}

export interface PcapJob {
  job_id: string;
  filename: string;
  status: 'queued' | 'processing' | 'done' | 'error';
  flows_processed: number;
  alerts_saved: number;
  error: string | null;
  started_at: string;
  finished_at: string | null;
}
