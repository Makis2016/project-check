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
  request?: string;
  response?: string;
  curl?: string;
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
  package_count?: number;
  hotfix_count?: number;
  update_count?: number;
  service_count?: number;
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

export interface HostInfo {
  id?: string;
  version_id?: string;
  name?: string;
  pretty?: string;
  kernel?: string;
  arch?: string;
  hostname?: string;
  user?: string;
  port?: number;
  target?: string;
  fingerprint?: string;
}

export interface HostUpdate {
  name: string;
  version: string;
  old_version?: string;
  repo?: string;
  arch?: string;
  security?: boolean;
}

export interface HostListener {
  proto: string;
  address: string;
  port: number;
  exposed: boolean;
}

export interface HostHotfix {
  id: string;
  description: string;
  installed_on: string;
}

export interface HostDefender {
  present?: boolean;
  antivirus?: boolean;
  realtime?: boolean;
  signature_age_days?: number | null;
}

export interface Discovery {
  endpoints: Endpoint[];
  tech: Tech[];
  docs: string[];
  pages: unknown[];
  js_files: string[];
  host?: HostInfo;
  packages?: { name: string; version: string }[];
  hotfixes?: HostHotfix[];
  updates?: HostUpdate[];
  services?: string[];
  listeners?: HostListener[];
  ssh?: Record<string, string>;
  firewall?: {
    active?: boolean;
    ufw?: boolean;
    firewalld?: boolean;
    nft?: boolean;
    iptables?: boolean;
    profiles?: { name: string; enabled: boolean }[];
  };
  security_modules?: { selinux?: string; apparmor?: string };
  defender?: HostDefender;
  smb1_enabled?: boolean;
  uid0_accounts?: string[];
  reboot_required?: boolean;
  autoupdate?: boolean;
  docker_socket?: Record<string, unknown>;
}

export interface ScanConfig {
  target: string;
  preset: string;
  scan_type?: "web" | "linux" | "windows";
  ssh_port?: number;
  ssh_user?: string;
  ssh_key_path?: string;
  rate_limit: number;
  max_pages: number;
  max_requests: number;
  scan_ports: boolean;
  subdomain_enum: boolean;
  active_checks: boolean;
  api_scan: boolean;
  quality_checks: boolean;
  auth_checks: boolean;
  intrusive_checks: boolean;
  secondary_cookie: string;
  ignore_tls: boolean;
  ports: number[];
  cookie: string;
  headers: Record<string, string>;
  proxy: string;
  exclude_paths: string[];
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
  scan_type?: "web" | "linux" | "windows";
  ssh_port?: number;
  ssh_user?: string;
  ssh_password?: string;
  ssh_key_path?: string;
  ssh_key_passphrase?: string;
  authorization_confirmed: boolean;
  cookie?: string;
  headers?: Record<string, string>;
  rate_limit?: number;
  max_pages?: number;
  active_checks?: boolean;
  api_scan?: boolean;
  scan_ports?: boolean;
  subdomain_enum?: boolean;
  quality_checks?: boolean;
  auth_checks?: boolean;
  intrusive_checks?: boolean;
  secondary_cookie?: string;
  ignore_tls?: boolean;
  ports?: number[];
  proxy?: string;
  exclude_paths?: string[];
}

export interface DiffSide {
  id: string;
  created_at: number;
  summary: Summary | null;
  preset: string;
}

export interface ScanDiff {
  available: boolean;
  reason?: string;
  base?: DiffSide;
  current?: DiffSide;
  counts?: { added: number; resolved: number; persisting: number };
  severity?: {
    added: Record<string, number>;
    resolved: Record<string, number>;
    persisting: Record<string, number>;
  };
  added?: Finding[];
  resolved?: Finding[];
  persisting?: Finding[];
}
