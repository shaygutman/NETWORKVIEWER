export type PlatformType = "cisco_ios" | "cisco_nxos" | "cisco_xe";
export type PortStatus = "up" | "down" | "admin-down" | "err-disabled" | "unknown";
export type NeighborDeviceType = "switch" | "phone" | "ap" | "server" | "host" | "unknown";

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
  /** Explicit IP alias from API (same value as ``ip``). */
  ip_address?: string;
  platform: PlatformType;
  site?: string | null;
  role?: string | null;
  reachable?: boolean | null;
  last_error?: string | null;
}

export interface PortDetail {
  port: string;
  status: PortStatus;
  /** Access VLAN ID, "trunk", "trunk (native N)", or "routed". */
  vlan?: string | null;
  /** Learned unicast MACs on this port from the cached MAC address table. */
  mac_addresses?: string[];
  duplex?: string | null;
  speed?: string | null;
  type?: string | null;
  description?: string | null;
  trust_level?: string | null;
  neighbor_hostname?: string | null;
  neighbor_ip?: string | null;
  neighbor_platform?: string | null;
  neighbor_port?: string | null;
  neighbor_protocol?: "cdp" | "lldp" | null;
  neighbor_device_type?: NeighborDeviceType | null;
  connected_device?: string | null;
  poe_status?: string | null;
  poe_watts?: number | null;
  poe_class?: string | null;
  poe_max_watts?: number | null;
  poe_high_draw?: boolean;
  err_disabled?: boolean;
  err_disabled_reason?: string | null;
  input_errors?: number | null;
  output_errors?: number | null;
  crc_errors?: number | null;
  frame_errors?: number | null;
  collisions?: number | null;
  duplex_mismatch?: boolean;
  high_errors?: boolean;
  down_since?: string | null;
  stale_days?: number | null;
  is_stale?: boolean;
  health_flags?: string[];
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
  /** Explicit IP alias from API (same value as ``ip``). */
  ip_address?: string;
  /** Real switch hostname from ``show hostname`` (e.g. eyok2-01sr-swc-01). */
  device_hostname?: string | null;
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
  poe_supported?: boolean | null;
  poe_used_watts?: number | null;
  poe_available_watts?: number | null;
  err_disabled_count?: number;
  stale_port_count?: number;
  health_warning_count?: number;
  error?: string | null;
}

export interface SwitchDetail extends SwitchOverview {
  interfaces: PortDetail[];
  recommended_commands: string[];
  stale_port_days_threshold?: number;
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
  from_cache?: boolean;
  /** Real Cisco hostname from show hostname (when known). */
  device_hostname?: string | null;
  /** edge = likely wall-jack; uplink = Po/Peer-Link flood; svi = Vlan ARP */
  port_role?: "edge" | "uplink" | "svi" | "unknown";
}

export interface MacLookupResponse {
  query: string;
  normalized_mac: string;
  hits: MacLookupHit[];
  devices_queried: number;
  devices_failed: number;
  devices_from_cache?: number;
  cache_fallback_used?: boolean;
  unreachable_hosts?: string[];
  warning?: string | null;
  errors: string[];
}

export interface TrackerHit {
  query_type: "ip" | "mac" | "hostname" | "neighbor" | "unknown";
  hostname: string;
  switch_ip: string;
  port?: string | null;
  vlan?: string | null;
  mac?: string | null;
  ip?: string | null;
  neighbor_hostname?: string | null;
  source: "mac" | "arp" | "neighbor" | "cache";
  detail?: string | null;
  from_cache?: boolean;
}

export interface TrackerSearchResponse {
  query: string;
  query_type: "ip" | "mac" | "hostname" | "neighbor" | "unknown";
  hits: TrackerHit[];
  devices_queried: number;
  devices_failed: number;
  devices_from_cache?: number;
  cache_fallback_used?: boolean;
  unreachable_hosts?: string[];
  warning?: string | null;
  errors: string[];
  searched_at: string;
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

/** Result of a read-only show-command execution on a switch. */
export interface ExecCommandResponse {
  hostname: string;
  command: string;
  output: string;
  success: boolean;
  error?: string | null;
  executed_at: string;
}

export type DashboardTab = "switches" | "mac" | "baseline";
