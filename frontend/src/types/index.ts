export type PlatformType = "cisco_ios" | "cisco_nxos" | "cisco_xe";
export type PortStatus = "up" | "down" | "admin-down" | "unknown";

export interface UserInfo {
  username: string;
  display_name?: string | null;
  email?: string | null;
  groups: string[];
  auth_mode: "ldap" | "mock";
}

export interface AuthToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: UserInfo;
}

export interface DeviceSummary {
  hostname: string;
  ip: string;
  platform: PlatformType;
  site?: string | null;
  role?: string | null;
  reachable?: boolean | null;
  last_error?: string | null;
}

export interface PortDetail {
  port: string;
  status: PortStatus;
  vlan?: string | null;
  duplex?: string | null;
  speed?: string | null;
  type?: string | null;
  description?: string | null;
  trust_level?: string | null;
  packets_in?: number | null;
  packets_out?: number | null;
  bytes_in?: number | null;
  bytes_out?: number | null;
  traffic_bps_in?: number | null;
  traffic_bps_out?: number | null;
}

export interface SwitchOverview {
  hostname: string;
  ip: string;
  platform: PlatformType;
  reachable: boolean;
  last_collected_at?: string | null;
  uptime?: string | null;
  model?: string | null;
  firmware?: string | null;
  system_mac?: string | null;
  dhcp_snooping?: boolean | null;
  igmp_snooping?: boolean | null;
  jumbo_frames?: boolean | null;
  cpu_percent?: number | null;
  interface_count: number;
  interfaces_up: number;
  interfaces_down: number;
  error?: string | null;
}

export interface SwitchDetail extends SwitchOverview {
  interfaces: PortDetail[];
  recommended_commands: string[];
}

/** Live SSH probe — always uses the logged-in UI session credentials. */
export interface ConnectivityProbeResult {
  hostname: string;
  ip: string;
  platform: PlatformType;
  credentials_source: "session";
  ssh_username: string;
  reachable: boolean;
  handshake_ok: boolean;
  authenticated: boolean;
  model?: string | null;
  firmware?: string | null;
  interface_count: number;
  interfaces_up: number;
  interfaces_down: number;
  error?: string | null;
  collected_at?: string | null;
}

export interface MacLookupHit {
  hostname: string;
  ip: string;
  mac: string;
  vlan?: string | null;
  port?: string | null;
  port_type?: string | null;
}

export interface MacLookupResponse {
  query: string;
  normalized_mac: string;
  hits: MacLookupHit[];
  devices_queried: number;
  devices_failed: number;
  errors: string[];
}

export interface BaselineDiffLine {
  tag: "equal" | "insert" | "delete" | "replace";
  baseline_line?: string | null;
  running_line?: string | null;
  line_no: number;
}

export interface BaselineDiffResponse {
  hostname: string;
  baseline_file: string;
  has_drift: boolean;
  added_lines: number;
  removed_lines: number;
  diff_lines: BaselineDiffLine[];
  collected_at: string;
  error?: string | null;
}

export type DashboardTab = "switches" | "mac" | "baseline";
