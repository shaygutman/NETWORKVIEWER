"""Strict Pydantic v2 schemas for API request/response contracts."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class PlatformType(str, Enum):
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    CISCO_XE = "cisco_xe"


class PortOperationalStatus(str, Enum):
    UP = "up"
    DOWN = "down"
    ADMIN_DOWN = "admin-down"
    ERR_DISABLED = "err-disabled"
    UNKNOWN = "unknown"


class NeighborDeviceType(str, Enum):
    SWITCH = "switch"
    PHONE = "phone"
    AP = "ap"
    SERVER = "server"
    HOST = "host"
    UNKNOWN = "unknown"


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=256)


class UserInfo(BaseModel):
    username: str
    display_name: str | None = None
    email: str | None = None
    groups: list[str] = Field(default_factory=list)
    auth_mode: Literal["ldap", "mock"] = "ldap"


class AuthToken(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserInfo


class DeviceInventoryItem(BaseModel):
    hostname: str
    ip: str
    platform: PlatformType
    credential_group: str = "default"
    site: str | None = None
    role: str | None = None
    baseline_file: str | None = None
    enabled: bool = True


class DeviceSummary(BaseModel):
    hostname: str
    ip: str
    platform: PlatformType
    site: str | None = None
    role: str | None = None
    reachable: bool | None = None
    last_error: str | None = None


class InterfaceStatus(BaseModel):
    port: str
    status: PortOperationalStatus
    vlan: str | None = None
    duplex: str | None = None
    speed: str | None = None
    type: str | None = None
    description: str | None = None
    trust_level: str | None = None


class PortDetail(BaseModel):
    port: str
    status: PortOperationalStatus
    # Access VLAN ID, "trunk", or "routed" from show interfaces status / switchport.
    vlan: str | None = None
    duplex: str | None = None
    speed: str | None = None
    type: str | None = None
    description: str | None = None
    trust_level: str | None = None
    # CDP/LLDP neighbor (read-only show neighbors detail) — optional when present.
    neighbor_hostname: str | None = None
    neighbor_ip: str | None = None
    neighbor_platform: str | None = None
    neighbor_port: str | None = None
    neighbor_protocol: Literal["cdp", "lldp"] | None = None
    neighbor_device_type: NeighborDeviceType | None = None
    connected_device: str | None = None
    # PoE (show power inline) — optional when unsupported.
    poe_status: str | None = None
    poe_watts: float | None = None
    poe_class: str | None = None
    poe_max_watts: float | None = None
    poe_high_draw: bool = False
    # Health / troubleshooting (read-only counters + status).
    err_disabled: bool = False
    err_disabled_reason: str | None = None
    input_errors: int | None = None
    output_errors: int | None = None
    crc_errors: int | None = None
    frame_errors: int | None = None
    collisions: int | None = None
    duplex_mismatch: bool = False
    high_errors: bool = False
    down_since: datetime | None = None
    stale_days: int | None = None
    is_stale: bool = False
    health_flags: list[str] = Field(default_factory=list)
    packets_in: int | None = None
    packets_out: int | None = None
    bytes_in: int | None = None
    bytes_out: int | None = None
    traffic_bps_in: float | None = None
    traffic_bps_out: float | None = None


class SwitchOverview(BaseModel):
    hostname: str
    ip: str
    platform: PlatformType
    reachable: bool
    last_collected_at: datetime | None = None
    uptime: str | None = None
    model: str | None = None
    firmware: str | None = None
    system_mac: str | None = None
    dhcp_snooping: bool | None = None
    igmp_snooping: bool | None = None
    jumbo_frames: bool | None = None
    cpu_percent: float | None = None
    interface_count: int = 0
    interfaces_up: int = 0
    interfaces_down: int = 0
    # PoE budget summary (null when PoE unsupported / unavailable).
    poe_supported: bool | None = None
    poe_used_watts: float | None = None
    poe_available_watts: float | None = None
    err_disabled_count: int = 0
    stale_port_count: int = 0
    health_warning_count: int = 0
    error: str | None = None


class SwitchDetail(SwitchOverview):
    interfaces: list[PortDetail] = Field(default_factory=list)
    recommended_commands: list[str] = Field(default_factory=list)
    stale_port_days_threshold: int = 30


class MacLookupRequest(BaseModel):
    mac: str = Field(min_length=4, max_length=32)
    hostname: str | None = None

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, value: str) -> str:
        cleaned = (
            value.strip()
            .lower()
            .replace(".", "")
            .replace(":", "")
            .replace("-", "")
            .replace(" ", "")
        )
        if len(cleaned) < 4 or any(c not in "0123456789abcdef" for c in cleaned):
            raise ValueError("MAC address must contain hex characters only")
        return cleaned


class MacLookupHit(BaseModel):
    hostname: str
    ip: str
    mac: str
    vlan: str | None = None
    port: str | None = None
    port_type: str | None = None


class MacLookupResponse(BaseModel):
    query: str
    normalized_mac: str
    hits: list[MacLookupHit]
    devices_queried: int
    devices_failed: int
    errors: list[str] = Field(default_factory=list)


class BaselineDiffLine(BaseModel):
    tag: Literal["equal", "insert", "delete", "replace"]
    baseline_line: str | None = None
    running_line: str | None = None
    line_no: int


class BaselineDiffResponse(BaseModel):
    hostname: str
    baseline_file: str
    has_drift: bool
    added_lines: int
    removed_lines: int
    diff_lines: list[BaselineDiffLine]
    collected_at: datetime
    error: str | None = None


class AuditEntry(BaseModel):
    timestamp: datetime
    username: str
    action: str
    detail: str
    success: bool = True
    hostname: str | None = None


class CliRecommendation(BaseModel):
    context: str
    commands: list[str]


class ExecCommandRequest(BaseModel):
    """Read-only CLI execution request — ``show`` commands only."""

    command: str = Field(min_length=5, max_length=256)

    @field_validator("command")
    @classmethod
    def strip_command(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("Command must not be empty")
        return cleaned


class ExecCommandResponse(BaseModel):
    """Output from a single read-only ``show`` command on a switch."""

    hostname: str
    command: str
    output: str
    success: bool
    error: str | None = None
    executed_at: datetime


class HealthResponse(BaseModel):
    status: str
    app: str
    version: str
    auth_mode: str
    device_count: int


class ConnectivityProbeResult(BaseModel):
    """Live SSH probe using the caller's in-memory login session credentials only."""

    hostname: str
    ip: str
    platform: PlatformType
    credentials_source: Literal["session"] = "session"
    ssh_username: str
    reachable: bool
    handshake_ok: bool
    authenticated: bool
    model: str | None = None
    firmware: str | None = None
    interface_count: int = 0
    interfaces_up: int = 0
    interfaces_down: int = 0
    error: str | None = None
    collected_at: datetime | None = None


class TrackerSearchRequest(BaseModel):
    query: str = Field(min_length=2, max_length=128)
    hostname: str | None = None


class TrackerHit(BaseModel):
    """Exact binding location for an IP / MAC / hostname / neighbor search hit."""

    query_type: Literal["ip", "mac", "hostname", "neighbor", "unknown"]
    hostname: str
    switch_ip: str
    port: str | None = None
    vlan: str | None = None
    mac: str | None = None
    ip: str | None = None
    neighbor_hostname: str | None = None
    source: Literal["mac", "arp", "neighbor", "cache"] = "cache"
    detail: str | None = None


class TrackerSearchResponse(BaseModel):
    query: str
    query_type: Literal["ip", "mac", "hostname", "neighbor", "unknown"]
    hits: list[TrackerHit] = Field(default_factory=list)
    devices_queried: int = 0
    devices_failed: int = 0
    errors: list[str] = Field(default_factory=list)
    searched_at: datetime
