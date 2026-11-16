export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Finding {
  check_id: string;
  title: string;
  severity: Severity;
  category: string;
  confidence: "high" | "medium" | "low" | string;
  url?: string;
  method?: string;
  param?: string;
  description?: string;
  evidence?: string;
  remediation?: string;
  cwe?: string;
  owasp?: string;
  references?: string[];
  fingerprint?: string;
}

export interface Summary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
  endpoint_count: number;
  page_count: number;
  request_count: number;
  duration_ms: number;
}

export interface PortInfo {
  port: number;
  service: string;
}

export interface AssetReport {
  resolved_ips: string[];
  open_ports: PortInfo[];
  tls: Record<string, unknown>;
  subdomains: string[];
}

export interface Endpoint {
  url: string;
  method: string;
  source: string;
  params: string[];
  status: number | null;
  content_type: string;
}

export interface Tech {
  name: string;
  version: string;
  evidence: string;
}

export interface Discovery {
  endpoints: Endpoint[];
  tech: Tech[];
  docs: string[];
  pages: unknown[];
  js_files: string[];
}

export interface ScanConfig {
  target: string;
  preset: string;
  rate_limit: number;
  max_pages: number;
  max_requests: number;
  scan_ports: boolean;
  subdomain_enum: boolean;
  active_checks: boolean;
  ignore_tls: boolean;
  ports: number[];
  cookie: string;
  headers: Record<string, string>;
}

export interface Scan {
  id: string;
  target: string;
  preset: string;
  status: "queued" | "running" | "completed" | "failed" | "stopped";
  created_at: number;
  finished_at: number | null;
  error: string | null;
  config: ScanConfig;
  summary: Summary | null;
  assets: AssetReport | null;
  discovery?: Discovery | null;
  findings?: Finding[];
  live?: boolean;
  live_findings?: Finding[];
  live_phase?: { phase: string; label: string; progress: number } | null;
}

export interface ScanEvent {
  type: string;
  [key: string]: unknown;
}

export interface LogEntry {
  id: number;
  level: string;
  message: string;
  time: string;
}

export interface ScanPayload {
  target: string;
  preset: string;
  authorization_confirmed: boolean;
  cookie?: string;
  headers?: Record<string, string>;
  rate_limit?: number;
  max_pages?: number;
  active_checks?: boolean;
  scan_ports?: boolean;
  subdomain_enum?: boolean;
  ignore_tls?: boolean;
  ports?: number[];
}
