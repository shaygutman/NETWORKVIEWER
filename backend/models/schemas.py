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
    vlan: str | None = None
    duplex: str | None = None
    speed: str | None = None
    type: str | None = None
    description: str | None = None
    trust_level: str | None = None
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
    error: str | None = None


class SwitchDetail(SwitchOverview):
    interfaces: list[PortDetail] = Field(default_factory=list)
    recommended_commands: list[str] = Field(default_factory=list)


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
