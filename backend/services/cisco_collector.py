"""Read-only Cisco SSH collector using Netmiko with concurrent execution.

SSH authentication uses ONLY the logged-in user's credentials from the
in-memory session store (populated at ``POST /api/auth/login`` from the
frontend). Environment variables such as ``SSH_TEST_USER`` /
``SSH_TEST_PASSWORD`` are never read for switch access.
"""

from __future__ import annotations

import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any

import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from backend.auth.session_store import DeviceCredentials
from backend.config import Settings, get_settings
from backend.models.schemas import (
    ConnectivityProbeResult,
    DeviceInventoryItem,
    InterfaceStatus,
    MacLookupHit,
    PlatformType,
    PortDetail,
    PortOperationalStatus,
    SwitchDetail,
    SwitchOverview,
)
from backend.services.collector_cache import collector_cache
from backend.services.inventory import load_inventory

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Client-side SSH crypto (Paramiko / Netmiko ONLY — never touch the switch)
# ---------------------------------------------------------------------------
# Older Catalyst / Nexus SSH stacks still offer legacy algorithms that Paramiko
# 5 removed. We pin Paramiko <5 in requirements and explicitly ensure the
# Python SSH *client* advertises these algorithms. Switches are never
# reconfigured.
_LEGACY_KEX = (
    "diffie-hellman-group-exchange-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group1-sha1",
)
_LEGACY_KEYS = (
    "ssh-rsa",
    "ssh-dss",
)
_LEGACY_CIPHERS = (
    "aes128-cbc",
    "aes192-cbc",
    "aes256-cbc",
    "3des-cbc",
)
_LEGACY_MACS = (
    "hmac-sha1",
    "hmac-sha1-96",
    "hmac-md5",
    "hmac-md5-96",
)

_legacy_ssh_lock = threading.Lock()
_legacy_ssh_enabled = False


def _extend_preferred(current: tuple[str, ...], extras: tuple[str, ...]) -> tuple[str, ...]:
    """Append missing algorithm names while preserving existing preference order."""
    seen = set(current)
    additions = tuple(name for name in extras if name not in seen)
    return current + additions if additions else current


def enable_legacy_ssh_algorithms() -> None:
    """
    Ensure Paramiko's SSH *client* can negotiate with legacy Cisco SSH stacks.

    Read-only / client-side only: mutates local Paramiko preferred-algorithm
    lists. Does not send any configuration commands to network devices.
    """
    global _legacy_ssh_enabled
    with _legacy_ssh_lock:
        if _legacy_ssh_enabled:
            return

        # Only re-add names that this Paramiko build still implements.
        kex_available = set(getattr(paramiko.Transport, "_kex_info", {}).keys())
        key_available = set(getattr(paramiko.Transport, "_key_info", {}).keys())
        cipher_available = set(getattr(paramiko.Transport, "_cipher_info", {}).keys())
        mac_available = set(getattr(paramiko.Transport, "_mac_info", {}).keys())

        paramiko.Transport._preferred_kex = _extend_preferred(
            tuple(paramiko.Transport._preferred_kex),
            tuple(k for k in _LEGACY_KEX if k in kex_available),
        )
        paramiko.Transport._preferred_keys = _extend_preferred(
            tuple(paramiko.Transport._preferred_keys),
            tuple(k for k in _LEGACY_KEYS if k in key_available),
        )
        # PubkeyAcceptedAlgorithms (client auth) — keep ssh-rsa usable too.
        if hasattr(paramiko.Transport, "_preferred_pubkeys"):
            paramiko.Transport._preferred_pubkeys = _extend_preferred(
                tuple(paramiko.Transport._preferred_pubkeys),
                tuple(k for k in _LEGACY_KEYS if k in key_available),
            )
        paramiko.Transport._preferred_ciphers = _extend_preferred(
            tuple(paramiko.Transport._preferred_ciphers),
            tuple(c for c in _LEGACY_CIPHERS if c in cipher_available),
        )
        paramiko.Transport._preferred_macs = _extend_preferred(
            tuple(paramiko.Transport._preferred_macs),
            tuple(m for m in _LEGACY_MACS if m in mac_available),
        )

        _legacy_ssh_enabled = True
        logger.info(
            "SSH client legacy algorithms enabled (Paramiko %s) — "
            "kex includes group14-sha1/group1-sha1; host keys include ssh-rsa. "
            "No switch-side SSH changes are made.",
            paramiko.__version__,
        )


# Apply once at import so every collector worker inherits the client policy.
enable_legacy_ssh_algorithms()

# Strict allow-list — configuration-modifying commands are never accepted.
READ_ONLY_COMMANDS: dict[str, list[str]] = {
    "overview": [
        "show version",
        "show interfaces status",
        "show processes cpu | include CPU utilization",
        "show mac address-table address",
    ],
    "ios": [
        "show version",
        "show interfaces status",
        "show interfaces counters",
        "show ip dhcp snooping",
        "show ip igmp snooping",
        "show system mtu",
        "show processes cpu | include CPU utilization",
        "show mac address-table",
        "show running-config",
    ],
    "nxos": [
        "show version",
        "show interface status",
        "show interface counters",
        "show ip dhcp snooping",
        "show ip igmp snooping",
        "show system jumbomtu",
        "show processes cpu | include CPU",
        "show mac address-table",
        "show running-config",
    ],
}

RECOMMENDED_COMMANDS: dict[str, list[str]] = {
    "switch": [
        "show version",
        "show interfaces status",
        "show processes cpu sorted",
        "show logging | include LINK-3-UPDOWN",
        "show spanning-tree summary",
        "show cdp neighbors",
        "show lldp neighbors",
        "show environment all",
    ],
    "port": [
        "show interfaces {port}",
        "show interfaces {port} status",
        "show interfaces {port} counters",
        "show interfaces {port} transceiver details",
        "show mac address-table interface {port}",
        "show running-config interface {port}",
        "show spanning-tree interface {port}",
    ],
}

# Port status tokens seen on Catalyst IOS / Nexus NX-OS.
_IFACE_STATUS_TOKENS = (
    "connected",
    "notconnect",
    "disabled",
    "err-disabled",
    "errdisabled",
    "inactive",
    "sfpAbsent",
    "xcvrAbsen",
    "noOperMem",
    "down",
    "up",
)

_CLI_ERROR_RE = re.compile(
    r"(syntax error|invalid (?:command|input)|ambiguous command|"
    r"%\s*invalid|unknown command|cmd exec error|"
    r"incorrect command|error:\s)",
    re.IGNORECASE,
)

_IFACE_NAME_RE = re.compile(
    r"^(?:"
    r"Ethernet|Eth|GigabitEthernet|Gi|FastEthernet|Fa|"
    r"TenGigabitEthernet|Te|TwentyFiveGigE|Twe|FortyGigabitEthernet|Fo|"
    r"HundredGigE|Hu|AppGigabitEthernet|Ap|Port-channel|Po|mgmt|"
    r"Vlan|Vl|Loopback|Lo|Tunnel|Tu"
    r")\S*$",
    re.IGNORECASE,
)


class CollectorError(Exception):
    """Raised for non-recoverable collector configuration issues."""


def collect_all_overviews(
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
    *,
    force_refresh: bool = False,
) -> list[SwitchOverview]:
    """Collect summary data from every enabled inventory device concurrently.

    Cached overviews are returned immediately unless ``force_refresh`` is set
    (manual Refresh). Uncached / expired devices are queried in parallel via
    a thread pool — never sequentially.
    """
    cfg = settings or get_settings()
    devices = load_inventory()
    if not devices:
        return []

    results: list[SwitchOverview] = []
    to_fetch: list[DeviceInventoryItem] = []

    if force_refresh:
        to_fetch = list(devices)
    else:
        for device in devices:
            cached = collector_cache.get_overview(device.hostname)
            if cached is not None:
                results.append(cached)
            else:
                to_fetch.append(device)

    if to_fetch:
        workers = max(1, min(cfg.collector_max_workers, len(to_fetch)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    collect_switch_overview,
                    device,
                    device_credentials,
                    cfg,
                    force_refresh=True,
                ): device
                for device in to_fetch
            }
            for future in as_completed(futures):
                device = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:  # noqa: BLE001
                    logger.exception("Unexpected collector failure for %s", device.hostname)
                    results.append(
                        SwitchOverview(
                            hostname=device.hostname,
                            ip=device.ip,
                            platform=device.platform,
                            reachable=False,
                            error=str(exc),
                        )
                    )

    results.sort(key=lambda item: item.hostname.lower())
    return results


def collect_switch_detail(
    hostname: str,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
    *,
    force_refresh: bool = False,
) -> SwitchDetail:
    """Return switch detail + interfaces, preferring the short-lived TTL cache."""
    cfg = settings or get_settings()
    device = _require_device(hostname)

    if not force_refresh:
        cached = collector_cache.get_detail(device.hostname)
        if cached is not None:
            logger.debug("Cache hit for switch detail %s", device.hostname)
            return cached

    overview, interfaces = _live_collect_overview_and_interfaces(
        device, device_credentials, cfg
    )
    detail = SwitchDetail(
        **overview.model_dump(),
        interfaces=interfaces,
        recommended_commands=RECOMMENDED_COMMANDS["switch"],
    )
    collector_cache.set_detail(device.hostname, detail, cfg.collector_cache_ttl_seconds)
    return detail


def collect_switch_overview(
    device: DeviceInventoryItem,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
    *,
    force_refresh: bool = False,
) -> SwitchOverview:
    """Collect (or return cached) overview for one inventory device."""
    cfg = settings or get_settings()

    if not force_refresh:
        cached = collector_cache.get_overview(device.hostname)
        if cached is not None:
            logger.debug("Cache hit for switch overview %s", device.hostname)
            return cached

    overview, interfaces = _live_collect_overview_and_interfaces(
        device, device_credentials, cfg
    )
    # Warm the detail cache when we already pulled interfaces in the same session.
    if overview.reachable:
        detail = SwitchDetail(
            **overview.model_dump(),
            interfaces=interfaces,
            recommended_commands=RECOMMENDED_COMMANDS["switch"],
        )
        collector_cache.set_detail(device.hostname, detail, cfg.collector_cache_ttl_seconds)
    else:
        collector_cache.set_overview(
            device.hostname, overview, cfg.collector_cache_ttl_seconds
        )
    return overview


def _live_collect_overview_and_interfaces(
    device: DeviceInventoryItem,
    device_credentials: DeviceCredentials,
    cfg: Settings,
) -> tuple[SwitchOverview, list[PortDetail]]:
    """
    Live read-only collection for one switch using a single SSH session.

    Opens one Netmiko connection, runs show commands, disconnects. Never sends
    configuration commands. Used to populate the TTL cache on miss / refresh.
    """
    connection = None
    params: dict[str, Any] = {}
    try:
        # First connect with inventory platform; may reconnect once if NX-OS/IOS
        # auto-detect disagrees (still read-only, still client-side only).
        params = _device_params(device, cfg, device_credentials)
        connection = ConnectHandler(**params)

        version_text = _send_command(connection, "show version", cfg, device.hostname)
        if _is_cli_error(version_text) or not version_text.strip():
            _log_raw_failure(device.hostname, "show version", version_text, "empty or CLI error")
            overview = SwitchOverview(
                hostname=device.hostname,
                ip=device.ip,
                platform=device.platform,
                reachable=False,
                error="show version failed or returned unusable output",
            )
            return overview, []

        platform = detect_platform(version_text, device.platform)
        if platform != device.platform:
            logger.info(
                "Platform auto-detect for %s (%s): inventory=%s detected=%s",
                device.hostname,
                device.ip,
                device.platform.value,
                platform.value,
            )
            # Reconnect with the correct Netmiko device_type for paging/prompts.
            try:
                connection.disconnect()
            except Exception:  # noqa: BLE001
                pass
            connection = None
            params = _device_params(
                device,
                cfg,
                device_credentials,
                device_type_override=_netmiko_device_type(platform),
            )
            connection = ConnectHandler(**params)
            # Re-fetch version on the corrected session (cheap, keeps parsers consistent).
            version_text = _send_command(connection, "show version", cfg, device.hostname) or version_text

        status_cmd = _iface_status_cmd(platform)
        cpu_cmd = _cpu_cmd(platform)
        mtu_cmd = _mtu_cmd(platform)
        follow_up = [
            status_cmd,
            cpu_cmd,
            "show ip dhcp snooping",
            "show ip igmp snooping",
            mtu_cmd,
        ]
        raw: dict[str, str] = {}
        for command in follow_up:
            raw[command] = _send_command(connection, command, cfg, device.hostname)

        iface_text, interfaces = _resolve_interfaces_on_connection(
            connection,
            cfg,
            device.hostname,
            platform,
            raw.get(status_cmd, ""),
        )
        up_count = sum(1 for i in interfaces if i.status == PortOperationalStatus.UP)
        down_count = len(interfaces) - up_count

        model = _extract_model(version_text)
        if not model:
            _log_raw_failure(
                device.hostname, "show version", version_text, "model parse returned None"
            )
        if not interfaces:
            _log_raw_failure(
                device.hostname,
                "interface status / ip interface brief",
                iface_text,
                "no interfaces parsed",
            )

        overview = SwitchOverview(
            hostname=device.hostname,
            ip=device.ip,
            platform=platform,
            reachable=True,
            last_collected_at=datetime.now(timezone.utc),
            uptime=_extract_uptime(version_text),
            model=model,
            firmware=_extract_firmware(version_text),
            system_mac=_extract_system_mac(version_text),
            dhcp_snooping=_detect_enabled(
                raw.get("show ip dhcp snooping", ""), "dhcp snooping is enabled"
            ),
            igmp_snooping=_detect_igmp(raw.get("show ip igmp snooping", "")),
            jumbo_frames=_detect_jumbo(raw.get(mtu_cmd, "")),
            cpu_percent=_extract_cpu(raw.get(cpu_cmd, "")),
            interface_count=len(interfaces),
            interfaces_up=up_count,
            interfaces_down=down_count,
            error=None,
        )
        port_details = [
            PortDetail(
                port=iface.port,
                status=iface.status,
                vlan=iface.vlan,
                duplex=iface.duplex,
                speed=iface.speed,
                type=iface.type,
                description=iface.description,
                trust_level=iface.trust_level,
            )
            for iface in interfaces
        ]
        return overview, port_details
    except Exception as exc:  # noqa: BLE001
        return (
            SwitchOverview(
                hostname=device.hostname,
                ip=device.ip,
                platform=device.platform,
                reachable=False,
                error=_friendly_error(exc),
            ),
            [],
        )
    finally:
        if "password" in params:
            params["password"] = ""
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:  # noqa: BLE001
                pass


def lookup_mac_across_inventory(
    mac_normalized: str,
    device_credentials: DeviceCredentials,
    hostname: str | None = None,
    settings: Settings | None = None,
) -> tuple[list[MacLookupHit], int, int, list[str]]:
    """Search MAC table(s). Returns hits, queried count, failed count, errors."""
    cfg = settings or get_settings()
    devices = load_inventory()
    if hostname:
        devices = [d for d in devices if d.hostname.lower() == hostname.lower()]

    hits: list[MacLookupHit] = []
    errors: list[str] = []
    failed = 0

    with ThreadPoolExecutor(max_workers=cfg.collector_max_workers) as pool:
        futures = {
            pool.submit(
                _lookup_mac_on_device,
                device,
                mac_normalized,
                device_credentials,
                cfg,
            ): device
            for device in devices
        }
        for future in as_completed(futures):
            device = futures[future]
            try:
                device_hits = future.result()
                hits.extend(device_hits)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                errors.append(f"{device.hostname}: {_friendly_error(exc)}")

    return hits, len(devices), failed, errors


def get_running_config(
    hostname: str,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
) -> str:
    cfg = settings or get_settings()
    device = _require_device(hostname)
    raw = _run_commands(device, ["show running-config"], cfg, device_credentials)
    return raw.get("show running-config", "")


def recommended_commands_for(context: str, port: str | None = None) -> list[str]:
    if context == "port" and port:
        return [cmd.format(port=port) for cmd in RECOMMENDED_COMMANDS["port"]]
    return list(RECOMMENDED_COMMANDS["switch"])


def probe_switch_connectivity(
    hostname: str,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
) -> ConnectivityProbeResult:
    """
    Live read-only connectivity probe using the caller's session credentials.

    Always bypasses the TTL cache (Test SSH). Performs a single-session live
    collect so model, firmware, and interface counts are validated without any
    env-var secrets, then refreshes the cache with the fresh snapshot.
    """
    cfg = settings or get_settings()
    device = _require_device(hostname)
    ssh_user = _require_session_credentials(device_credentials).username

    collector_cache.invalidate(device.hostname)
    overview, interfaces = _live_collect_overview_and_interfaces(
        device, device_credentials, cfg
    )
    if overview.reachable:
        detail = SwitchDetail(
            **overview.model_dump(),
            interfaces=interfaces,
            recommended_commands=RECOMMENDED_COMMANDS["switch"],
        )
        collector_cache.set_detail(device.hostname, detail, cfg.collector_cache_ttl_seconds)
    else:
        collector_cache.set_overview(
            device.hostname, overview, cfg.collector_cache_ttl_seconds
        )

    iface_count = len(interfaces) if interfaces else overview.interface_count
    up_count = (
        sum(1 for i in interfaces if i.status == PortOperationalStatus.UP)
        if interfaces
        else overview.interfaces_up
    )
    down_count = iface_count - up_count if interfaces else overview.interfaces_down

    err_lower = (overview.error or "").lower()
    handshake_failed = any(
        token in err_lower
        for token in (
            "kex",
            "host key",
            "incompatible",
            "timed out",
            "unreachable",
            "network error",
        )
    )
    auth_failed = "authentication" in err_lower
    handshake_ok = overview.reachable or auth_failed or (bool(overview.error) and not handshake_failed)

    return ConnectivityProbeResult(
        hostname=device.hostname,
        ip=device.ip,
        platform=overview.platform,
        credentials_source="session",
        ssh_username=ssh_user,
        reachable=overview.reachable,
        handshake_ok=bool(handshake_ok),
        authenticated=overview.reachable,
        model=overview.model,
        firmware=overview.firmware,
        interface_count=iface_count,
        interfaces_up=up_count,
        interfaces_down=down_count,
        error=overview.error,
        collected_at=overview.last_collected_at or datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _require_device(hostname: str) -> DeviceInventoryItem:
    for device in load_inventory():
        if device.hostname.lower() == hostname.lower():
            return device
    raise CollectorError(f"Device '{hostname}' not found in inventory")


def _require_session_credentials(device_credentials: DeviceCredentials) -> DeviceCredentials:
    """Fail fast if session credentials are missing — never fall back to env vars."""
    username = (device_credentials.username or "").strip()
    password = device_credentials.password or ""
    if not username or not password:
        raise CollectorError(
            "Session SSH credentials unavailable. Sign in again via the UI "
            "(credentials come from your login session only — not from environment variables)."
        )
    return DeviceCredentials(username=username, password=password)


def _netmiko_device_type(platform: PlatformType) -> str:
    return "cisco_nxos" if platform == PlatformType.CISCO_NXOS else "cisco_ios"


def _device_params(
    device: DeviceInventoryItem,
    cfg: Settings,
    device_credentials: DeviceCredentials,
    device_type_override: str | None = None,
) -> dict[str, Any]:
    """Build Netmiko params from the logged-in user's in-memory session credentials.

    Credentials MUST be supplied by the API session context (frontend login).
    This function never reads ``SSH_TEST_*``, ``.env`` secrets, or inventory
    passwords. SSH crypto is client-side only (``enable_legacy_ssh_algorithms``).
    """
    enable_legacy_ssh_algorithms()
    session_creds = _require_session_credentials(device_credentials)
    device_type = device_type_override or _netmiko_device_type(device.platform)

    # Warn loudly if an incompatible Paramiko major landed in the venv —
    # preferred-list tweaks cannot resurrect algorithms removed in Paramiko 5+.
    try:
        major = int(str(paramiko.__version__).split(".", maxsplit=1)[0])
    except ValueError:
        major = 0
    if major >= 5:
        logger.error(
            "Paramiko %s removed legacy SSH algorithms required by enterprise "
            "Cisco gear. Install paramiko>=3.4,<5 (client-side only).",
            paramiko.__version__,
        )

    return {
        "device_type": device_type,
        "host": device.ip,
        "username": session_creds.username,
        "password": session_creds.password,
        "secret": None,
        "timeout": cfg.ssh_timeout,
        "conn_timeout": cfg.ssh_conn_timeout,
        "fast_cli": False,
        "session_log": None,
        # Do not strip algorithms — empty disables nothing; we rely on the
        # extended Paramiko preferred lists for legacy Cisco negotiation.
        "disabled_algorithms": {},
        # Password auth only from the UI session; never agent/key files/.env.
        "allow_agent": False,
        "use_keys": False,
    }


def _send_command(connection: Any, command: str, cfg: Settings, hostname: str) -> str:
    """Send one read-only show/ping command on an open Netmiko session."""
    if not _is_read_only(command):
        logger.warning("Blocked non-read-only command: %s", command)
        return ""
    try:
        raw_out = connection.send_command(
            command,
            read_timeout=cfg.ssh_timeout,
            use_textfsm=False,
        )
        text = normalize_cli_text(str(raw_out or ""))
        if _is_cli_error(text):
            _log_raw_failure(hostname, command, text, "CLI reported an error")
        return text
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "Command failed on %s (%s): %s — %s",
            hostname,
            command,
            exc.__class__.__name__,
            exc,
        )
        _log_raw_failure(
            hostname,
            command,
            "",
            f"exception during send_command: {exc.__class__.__name__}: {exc}",
        )
        return ""


def _run_commands(
    device: DeviceInventoryItem,
    commands: list[str],
    cfg: Settings,
    device_credentials: DeviceCredentials,
    device_type_override: str | None = None,
) -> dict[str, str]:
    params = _device_params(device, cfg, device_credentials, device_type_override)
    outputs: dict[str, str] = {}
    connection = None
    try:
        connection = ConnectHandler(**params)
        for command in commands:
            outputs[command] = _send_command(connection, command, cfg, device.hostname)
        return outputs
    finally:
        # Scrub password from the local params dict; never log it
        if "password" in params:
            params["password"] = ""
        if connection is not None:
            try:
                connection.disconnect()
            except Exception:  # noqa: BLE001
                pass


def _is_read_only(command: str) -> bool:
    normalized = " ".join(command.strip().lower().split())
    if not normalized.startswith("show ") and not normalized.startswith("ping "):
        return False
    blocked = (
        "configure",
        "conf t",
        "write",
        "wr ",
        "copy running",
        "reload",
        "erase",
        "delete",
        "clear ",
        "debug ",
    )
    return not any(token in normalized for token in blocked)


def _lookup_mac_on_device(
    device: DeviceInventoryItem,
    mac_normalized: str,
    device_credentials: DeviceCredentials,
    cfg: Settings,
) -> list[MacLookupHit]:
    cisco_mac = _to_cisco_mac(mac_normalized)
    command = f"show mac address-table | include {cisco_mac}"
    # Broader fallback if include filter yields nothing useful
    raw = _run_commands(
        device,
        [command, "show mac address-table"],
        cfg,
        device_credentials,
    )
    text = raw.get(command) or raw.get("show mac address-table", "")
    if _is_cli_error(text) or not text.strip():
        _log_raw_failure(device.hostname, "show mac address-table", text, "MAC lookup empty/error")
    hits = parse_mac_table(text, device.hostname, device.ip)
    needle = mac_normalized.lower()
    return [
        hit
        for hit in hits
        if needle in hit.mac.replace(".", "").replace(":", "").replace("-", "").lower()
    ]


def _resolve_interfaces_on_connection(
    connection: Any,
    cfg: Settings,
    hostname: str,
    platform: PlatformType,
    primary_text: str,
) -> tuple[str, list[InterfaceStatus]]:
    """Parse interface status with OS command fallbacks on the open SSH session."""
    candidates: list[tuple[str, str]] = []
    primary_cmd = _iface_status_cmd(platform)
    alternate_cmd = (
        "show interfaces status"
        if platform == PlatformType.CISCO_NXOS
        else "show interface status"
    )
    candidates.append((primary_cmd, primary_text))

    interfaces = parse_interface_status(primary_text)
    if interfaces:
        return primary_text, interfaces

    if _is_cli_error(primary_text) or not primary_text.strip() or not interfaces:
        logger.info(
            "Primary interface status failed on %s — trying alternate command %r",
            hostname,
            alternate_cmd,
        )
        alt_text = _send_command(connection, alternate_cmd, cfg, hostname)
        candidates.append((alternate_cmd, alt_text))
        interfaces = parse_interface_status(alt_text)
        if interfaces:
            return alt_text, interfaces

    # Last resort: show ip interface brief (both IOS and NX-OS accept this).
    brief_cmd = "show ip interface brief"
    logger.info("Falling back to %r on %s", brief_cmd, hostname)
    brief_text = _send_command(connection, brief_cmd, cfg, hostname)
    candidates.append((brief_cmd, brief_text))
    interfaces = parse_ip_interface_brief(brief_text)
    if interfaces:
        return brief_text, interfaces

    for _cmd, text in reversed(candidates):
        if text.strip():
            return text, []
    return primary_text, []


def _iface_status_cmd(platform: PlatformType) -> str:
    return "show interface status" if platform == PlatformType.CISCO_NXOS else "show interfaces status"


def _cpu_cmd(platform: PlatformType) -> str:
    if platform == PlatformType.CISCO_NXOS:
        return "show processes cpu | include CPU"
    return "show processes cpu | include CPU utilization"


def _mtu_cmd(platform: PlatformType) -> str:
    return "show system jumbomtu" if platform == PlatformType.CISCO_NXOS else "show system mtu"


def _friendly_error(exc: Exception) -> str:
    if isinstance(exc, NetmikoTimeoutException):
        return "Connection timed out — device unreachable or SSH port closed"
    if isinstance(exc, NetmikoAuthenticationException):
        return "SSH authentication failed — your ENT account may lack access on this switch"
    if isinstance(exc, OSError):
        return f"Network error: {exc}"
    # Never include exception args that might echo credentials
    return exc.__class__.__name__


def _is_cli_error(text: str) -> bool:
    if not text or not text.strip():
        return False
    return bool(_CLI_ERROR_RE.search(text))


def _log_raw_failure(hostname: str, command: str, raw: str, reason: str) -> None:
    """Print raw CLI to the terminal/logs when command or parse fails."""
    preview = raw if raw.strip() else "<empty>"
    # Cap extremely large dumps but keep enough for debugging status tables.
    if len(preview) > 12000:
        preview = preview[:12000] + "\n... [truncated] ..."
    logger.error(
        "Collector parse/command failure on %s | cmd=%r | reason=%s | raw_cli:\n%s",
        hostname,
        command,
        reason,
        preview,
    )


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------


def normalize_cli_text(output: str) -> str:
    """Normalize BOM / mixed CR-LF artifacts from captured switch logs and SSH."""
    if not output:
        return ""
    text = output.replace("\ufeff", "")
    # Files saved on Windows from some terminals use \r\r\n; collapse to \n.
    text = text.replace("\r\r\n", "\n").replace("\r\n", "\n").replace("\r", "\n")
    return text


def detect_platform(version_text: str, fallback: PlatformType) -> PlatformType:
    """Infer IOS vs NX-OS from show version (corrects mislabeled inventory)."""
    text = normalize_cli_text(version_text)
    lowered = text.lower()
    if "nx-os" in lowered or "cisco nexus operating system" in lowered or re.search(
        r"^\s*NXOS:\s*version", text, re.I | re.M
    ):
        return PlatformType.CISCO_NXOS
    if "ios xe" in lowered or "ios-xe" in lowered:
        return PlatformType.CISCO_XE
    if "cisco ios software" in lowered or "cisco ios xe software" in lowered:
        return PlatformType.CISCO_IOS
    return fallback


def parse_interface_status(output: str) -> list[InterfaceStatus]:
    """
    Parse `show interfaces status` / `show interface status` tabular output.

    Regex is preferred (Cisco right-aligns Duplex/Speed so fixed header offsets
    mis-slice values like ``a-1000``). Column-assisted parsing is the fallback.
    """
    text = normalize_cli_text(output)
    if _is_cli_error(text):
        return []

    results = _parse_interface_status_by_regex(text)
    if results:
        return results
    return _parse_interface_status_by_columns(text)


def _parse_interface_status_by_regex(output: str) -> list[InterfaceStatus]:
    status_alt = "|".join(_IFACE_STATUS_TOKENS)
    # When Name is empty there is only one whitespace run between port and status.
    pattern_no_desc = re.compile(
        rf"^(?P<port>\S+)"
        rf"\s+(?P<status>{status_alt})"
        rf"\s+(?P<vlan>\S+)"
        rf"\s+(?P<duplex>\S+)"
        rf"\s+(?P<speed>\S+)"
        rf"(?:\s+(?P<type>.+))?$",
        re.IGNORECASE,
    )
    # Status-anchored: everything between port and status is the description,
    # which may contain spaces (e.g. ``*** AP ***``, ``** LCOV-Security *``).
    pattern_with_desc = re.compile(
        rf"^(?P<port>\S+)\s+"
        rf"(?P<desc>.+?)\s+"
        rf"(?P<status>{status_alt})\s+"
        rf"(?P<vlan>\S+)\s+"
        rf"(?P<duplex>\S+)\s+"
        rf"(?P<speed>\S+)"
        rf"(?:\s+(?P<type>.+))?$",
        re.IGNORECASE,
    )

    results: list[InterfaceStatus] = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("port") or stripped.startswith("---"):
            continue

        match = pattern_no_desc.match(stripped)
        desc: str | None = None
        if match and _looks_like_interface(match.group("port")):
            # Prefer no-desc only when the token after the port is truly a status
            # (already enforced by the regex). Otherwise fall through.
            pass
        else:
            match = pattern_with_desc.match(stripped)
            if not match:
                continue
            desc = (match.group("desc") or "").strip() or None

        port = match.group("port")
        if not _looks_like_interface(port):
            continue
        results.append(
            InterfaceStatus(
                port=port,
                status=_map_port_status(match.group("status")),
                vlan=_normalize_vlan(match.group("vlan")),
                duplex=match.group("duplex"),
                speed=match.group("speed"),
                type=(match.group("type") or "").strip() or None,
                description=desc,
                trust_level=None,
            )
        )
    return results


def _parse_interface_status_by_columns(output: str) -> list[InterfaceStatus]:
    """Fallback when regex fails: slice Port/Name/Status/Vlan, split the tail."""
    lines = output.splitlines()
    header_idx = -1
    header_line = ""
    for idx, line in enumerate(lines):
        lowered = line.lower()
        if "port" in lowered and "status" in lowered and "vlan" in lowered:
            header_idx = idx
            header_line = line
            break
    if header_idx < 0:
        return []

    header_lower = header_line.lower()
    port_at = header_lower.find("port")
    name_at = header_lower.find("name")
    status_at = header_lower.find("status")
    vlan_at = header_lower.find("vlan")
    duplex_at = header_lower.find("duplex")
    if min(port_at, status_at, vlan_at) < 0:
        return []
    # Name column is optional on some NX-OS banners.
    name_end = status_at
    if name_at < 0:
        name_at = port_at + 1
        while name_at < len(header_line) and not header_line[name_at].isspace():
            name_at += 1
        while name_at < len(header_line) and header_line[name_at].isspace():
            name_at += 1

    results: list[InterfaceStatus] = []
    for line in lines[header_idx + 1 :]:
        raw_line = line.rstrip("\n")
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("---") or stripped.startswith("==="):
            continue

        port = raw_line[port_at:name_at].strip() if name_at > port_at else stripped.split()[0]
        if not port or not _looks_like_interface(port):
            continue
        desc = raw_line[name_at:status_at].strip() if status_at > name_at else ""
        status_raw = raw_line[status_at:vlan_at].strip() if vlan_at > status_at else ""
        if not status_raw or status_raw.lower() in {"status", "type", "vlan"}:
            continue

        # Duplex/Speed are right-aligned and overflow header keywords; split the tail.
        tail_start = duplex_at if duplex_at > vlan_at else vlan_at
        vlan_field = raw_line[vlan_at:tail_start].strip() if tail_start > vlan_at else ""
        if not vlan_field:
            # vlan may sit in the status→end region — re-tokenize from status onward
            after_status = raw_line[status_at:].split()
            if len(after_status) < 4:
                continue
            status_raw = after_status[0]
            vlan_field = after_status[1]
            duplex = after_status[2]
            speed = after_status[3]
            port_type = " ".join(after_status[4:]) or None
        else:
            tail_tokens = raw_line[tail_start:].split()
            if len(tail_tokens) < 2:
                continue
            duplex = tail_tokens[0]
            speed = tail_tokens[1]
            port_type = " ".join(tail_tokens[2:]) or None

        results.append(
            InterfaceStatus(
                port=port,
                status=_map_port_status(status_raw),
                vlan=_normalize_vlan(vlan_field),
                duplex=duplex,
                speed=speed,
                type=port_type,
                description=desc or None,
                trust_level=None,
            )
        )
    return results


def parse_ip_interface_brief(output: str) -> list[InterfaceStatus]:
    """Regex fallback for `show ip interface brief` (IOS + NX-OS)."""
    text = normalize_cli_text(output)
    if _is_cli_error(text):
        return []

    results: list[InterfaceStatus] = []
    # IOS: Interface IP-Address OK? Method Status Protocol
    ios_re = re.compile(
        r"^(?P<port>\S+)\s+"
        r"(?P<ip>\S+)\s+"
        r"(?P<ok>YES|NO)\s+"
        r"(?P<method>\S+)\s+"
        r"(?P<status>up|down|administratively down|deleted|reset)\s+"
        r"(?P<protocol>up|down)",
        re.IGNORECASE,
    )
    # NX-OS: Interface IP-Address Status Protocol Reason (optional extras)
    nx_re = re.compile(
        r"^(?P<port>\S+)\s+"
        r"(?P<ip>\S+)\s+"
        r"(?P<status>up|down|admin-down|administratively down|none)\s+"
        r"(?P<protocol>\S+)",
        re.IGNORECASE,
    )

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lowered = stripped.lower()
        if lowered.startswith("interface") or lowered.startswith("---"):
            continue

        match = ios_re.match(stripped) or nx_re.match(stripped)
        if not match:
            continue
        port = match.group("port")
        if not _looks_like_interface(port):
            continue
        results.append(
            InterfaceStatus(
                port=port,
                status=_map_port_status(match.group("status")),
                vlan=None,
                duplex=None,
                speed=None,
                type=None,
                description=None,
                trust_level=None,
            )
        )
    return results


def parse_mac_table(output: str, hostname: str, ip: str) -> list[MacLookupHit]:
    """Parse IOS / NX-OS MAC address tables with tolerant whitespace handling."""
    text = normalize_cli_text(output)
    if _is_cli_error(text):
        return []

    hits: list[MacLookupHit] = []
    # IOS classic: VLAN MAC Type Learn Ports  OR  VLAN MAC Type Ports
    # NX-OS: VLAN MAC Type Age Secure NTFY Ports
    patterns = [
        re.compile(
            r"(?P<vlan>\*?\d+)\s+"
            r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
            r"(?P<type>dynamic|static|static\s*\(C\)|system|G)\s+"
            r"(?:(?:\S+)\s+){0,4}"
            r"(?P<port>\S+)\s*$",
            re.IGNORECASE,
        ),
        re.compile(
            r"(?P<vlan>\*?\d+)\s+"
            r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
            r"(?P<type>\S+)\s+"
            r".*?"
            r"(?P<port>(?:Ethernet|Eth|Gi|Te|Fa|Po|Port-channel|Vlan|Vl)\S*)\s*$",
            re.IGNORECASE,
        ),
    ]

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("vlan") or stripped.startswith("---"):
            continue
        for pattern in patterns:
            match = pattern.search(stripped)
            if not match:
                continue
            port = match.group("port")
            if port.lower() in {"ports", "port", "cpu", "drop", "––", "--"}:
                continue
            hits.append(
                MacLookupHit(
                    hostname=hostname,
                    ip=ip,
                    mac=match.group("mac").lower(),
                    vlan=match.group("vlan").lstrip("*"),
                    port=port,
                    port_type=match.group("type").split()[0],
                )
            )
            break
    return hits


def _looks_like_interface(port: str) -> bool:
    if _IFACE_NAME_RE.match(port):
        return True
    # Accept abbreviated / numeric module forms like Eth1/1, Gi1/0/1 already covered.
    return bool(re.match(r"^[A-Za-z][A-Za-z0-9\-/]+$", port)) and not port.lower().startswith(
        ("total", "legend", "codes")
    )


def _normalize_vlan(vlan: str | None) -> str | None:
    if not vlan:
        return None
    value = vlan.strip()
    if not value:
        return None
    lowered = value.lower()
    if lowered in {"trunk", "routed", "unassigned", "--", "––"}:
        return lowered if lowered in {"trunk", "routed"} else value
    return value


def _map_port_status(raw: str) -> PortOperationalStatus:
    value = raw.lower().strip()
    if value in {"connected", "up"}:
        return PortOperationalStatus.UP
    if value in {"disabled", "admin-down", "administratively down"}:
        return PortOperationalStatus.ADMIN_DOWN
    if value in {
        "notconnect",
        "err-disabled",
        "errdisabled",
        "inactive",
        "sfabsent",
        "sfpabsent",
        "xcvrabsen",
        "noopermem",
        "down",
        "deleted",
        "reset",
        "none",
    }:
        return PortOperationalStatus.DOWN
    return PortOperationalStatus.UNKNOWN


def _extract_uptime(version_text: str) -> str | None:
    text = normalize_cli_text(version_text)
    patterns = [
        r"[Kk]ernel\s+[Uu]ptime\s+is\s+(.+)",
        r"[Uu]ptime\s+is\s+(.+)",
        r"Switch\s+[Uu]ptime\s*:\s*(.+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip()
    return None


def _extract_model(version_text: str) -> str | None:
    text = normalize_cli_text(version_text)
    patterns = [
        # Catalyst inventory block
        r"Model\s+[Nn]umber\s*:\s*(\S+)",
        # classic / XE: cisco C9300-48U (X86) processor ...
        r"cisco\s+(\S+)\s+\(",
        # Nexus: cisco Nexus9000 C93180YC-FX3 Chassis / cisco Nexus9000 93180YC-EX chassis
        r"cisco\s+(Nexus\S+(?:\s+\S+){0,3}?)\s+[Cc]hassis",
        r"Hardware:\s+(\S+),",
        # Stack table: "1 52 WS-C2960XR-48FPD-I 15.0(2)EX5 ..."
        r"^\s*\*?\s*\d+\s+\d+\s+(\S+)\s+\S+\s+\S+",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            model = match.group(1).strip()
            # Prefer the specific PID when Nexus returns "Nexus9000 C93180YC-FX3"
            parts = model.split()
            if len(parts) >= 2 and parts[0].lower().startswith("nexus"):
                # Use the chassis PID token when present (C93180YC-FX3 or 93180YC-EX)
                return " ".join(parts)
            return model
    return None


def _extract_firmware(version_text: str) -> str | None:
    text = normalize_cli_text(version_text)
    patterns = [
        r"Cisco IOS XE Software,\s+Version\s+(\S+)",
        r"Cisco IOS Software.*,\s+Version\s+([^,\s]+)",
        r"NXOS:\s+version\s+(\S+)",
        r"system:\s+version\s+(\S+)",
        r"Software\s+\(.*?\)\s*,\s*Version\s+([^,\s]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(",")
    return None


def _extract_system_mac(version_text: str) -> str | None:
    text = normalize_cli_text(version_text)
    patterns = [
        r"(?:Base|System)\s+ethernet\s+MAC\s+[Aa]ddress\s*:\s*([0-9a-fA-F:\.\-]+)",
        r"Public\s+Key\s+Algorithm.*?MAC\s+[Aa]ddress\s*:\s*([0-9a-fA-F:\.\-]+)",
        r"System\s+MAC\s+[Aa]ddress\s*:\s*([0-9a-fA-F:\.\-]+)",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).lower()
    return None


def _extract_cpu(cpu_text: str) -> float | None:
    text = normalize_cli_text(cpu_text)
    match = re.search(r"CPU utilization.*?,\s*(\d+(?:\.\d+)?)\s*%\s*five", text, re.I)
    if match:
        return float(match.group(1))
    # NX-OS: CPU states / five seconds ... or "CPU util  ..."
    match = re.search(
        r"(?:five seconds|CPU(?:\s+util(?:ization)?)?).*?(\d+(?:\.\d+)?)\s*%",
        text,
        re.I,
    )
    if match:
        return float(match.group(1))
    match = re.search(r"(\d+(?:\.\d+)?)\s*%", text)
    return float(match.group(1)) if match else None


def _detect_enabled(text: str, needle: str) -> bool | None:
    if not text.strip() or _is_cli_error(text):
        return None
    return needle.lower() in text.lower()


def _detect_igmp(text: str) -> bool | None:
    if not text.strip() or _is_cli_error(text):
        return None
    lowered = text.lower()
    if "globally enabled" in lowered or "igmp snooping is globally enabled" in lowered:
        return True
    if "globally disabled" in lowered:
        return False
    return "enabled" in lowered


def _detect_jumbo(text: str) -> bool | None:
    if not text.strip() or _is_cli_error(text):
        return None
    match = re.search(r"(?:System MTU|jumbomtu|Jumbo)\D+(\d+)", text, re.I)
    if match:
        return int(match.group(1)) > 1500
    return "jumbo" in text.lower()


def _to_cisco_mac(normalized: str) -> str:
    """Convert aabbccddeeff (or partial) into Cisco dotted form when possible."""
    hex_only = normalized.lower()
    if len(hex_only) == 12:
        return f"{hex_only[0:4]}.{hex_only[4:8]}.{hex_only[8:12]}"
    return hex_only
