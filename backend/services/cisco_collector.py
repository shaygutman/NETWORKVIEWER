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
from typing import Any, Literal

import paramiko
from netmiko import ConnectHandler
from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException

from backend.auth.session_store import DeviceCredentials
from backend.config import Settings, get_settings
from backend.models.schemas import (
    ConnectivityProbeResult,
    DeviceInventoryItem,
    ExecCommandResponse,
    InterfaceStatus,
    MacLookupHit,
    PlatformType,
    PortDetail,
    PortOperationalStatus,
    SwitchDetail,
    SwitchOverview,
)
from backend.services.collector_cache import TrackerIndexEntry, collector_cache
from backend.services.inventory import load_inventory
from backend.services.poe_health import (
    classify_neighbor,
    detect_duplex_mismatch,
    is_high_error_rate,
    parse_arp_table,
    parse_counters_errors,
    parse_errdisabled_reasons,
    parse_power_inline,
)

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
        "show vlan brief",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
    ],
    "ios": [
        "show version",
        "show interfaces status",
        "show interfaces counters",
        "show vlan brief",
        "show interfaces switchport",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show power inline",
        "show interfaces counters errors",
        "show interfaces status err-disabled",
        "show ip arp",
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
        "show vlan brief",
        "show interface switchport",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show power inline",
        "show interface counters errors",
        "show interface status err-disabled",
        "show ip arp",
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
        "show inventory",
        "show interfaces status",
        "show interfaces status err-disabled",
        "show interfaces counters errors",
        "show processes cpu sorted",
        "show processes memory sorted",
        "show logging | include LINK-3-UPDOWN",
        "show logging | include %LINEPROTO",
        "show spanning-tree summary",
        "show spanning-tree root",
        "show vlan brief",
        "show etherchannel summary",
        "show ip interface brief",
        "show ip route summary",
        "show ip arp",
        "show mac address-table count",
        "show cdp neighbors detail",
        "show lldp neighbors detail",
        "show power inline",
        "show environment all",
        "show env temperature status",
        "show module",
        "show boot",
        "show reload",
        "show clock",
        "show users",
        "show snmp community",
        "show ip dhcp snooping",
        "show ip dhcp snooping binding",
        "show ip igmp snooping",
        "show storm-control",
        "show port-security",
    ],
    "port": [
        "show run interface {port}",
        "show run interfaces {port}",
        "show run interfaces {port} status",
        "show run interfaces {port} switchport",
        "show run interfaces {port} counters",
        "show run interfaces {port} counters errors",
        "show run interfaces {port} transceiver details",
        "show run interfaces {port} description",
        "show mac address-table interface {port}",
        "show cdp neighbors {port} detail",
        "show lldp neighbors {port} detail",
        "show spanning-tree interface {port}",
        "show spanning-tree interface {port} detail",
        "show power inline {port}",
        "show ip interface {port}",
        "show etherchannel {port} port-channel",
        "show storm-control {port}",
        "show port-security interface {port}",
        "show ip dhcp snooping binding interface {port}",
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


class CommandRejectedError(Exception):
    """Raised when a CLI command fails the read-only ``show`` safety gate."""


def list_cached_overviews(settings: Settings | None = None) -> list[SwitchOverview]:
    """
    Cache-only fleet overview for GUI GETs — never opens SSH.

    Missing hosts are returned as placeholders so the UI stays instantaneous
    until the background poller (or a manual Refresh) fills the cache.
    """
    cfg = settings or get_settings()
    devices = load_inventory()
    results: list[SwitchOverview] = []
    for device in devices:
        cached = collector_cache.get_overview(device.hostname, sticky=True)
        if cached is not None:
            results.append(cached)
            continue
        results.append(
            SwitchOverview(
                hostname=device.hostname,
                ip=device.ip,
                platform=device.platform,
                reachable=False,
                error="Awaiting first background collection (cache miss)",
            )
        )
    results.sort(key=lambda item: item.hostname.lower())
    logger.debug(
        "Served %s cached overview(s) with no SSH (ttl=%ss)",
        len(results),
        cfg.collector_cache_ttl_seconds,
    )
    return results


def get_cached_detail(
    hostname: str,
    settings: Settings | None = None,
) -> SwitchDetail | None:
    """Cache-only switch detail for GUI GETs — never opens SSH."""
    cfg = settings or get_settings()
    device = _require_device(hostname)
    cached = collector_cache.get_detail(device.hostname, sticky=True)
    if cached is not None:
        logger.debug("Sticky cache hit for switch detail %s", device.hostname)
        return cached
    logger.debug(
        "No cached detail for %s (ttl window %ss) — GUI should wait for poll/refresh",
        device.hostname,
        cfg.collector_cache_ttl_seconds,
    )
    return None


def collect_all_overviews(
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
    *,
    force_refresh: bool = False,
) -> list[SwitchOverview]:
    """Collect summary data from every enabled inventory device concurrently.

    When ``force_refresh`` is False this still returns sticky cache hits and
    only SSHs devices with no snapshot (legacy path). Prefer
    ``list_cached_overviews`` for GUI GETs. Manual Refresh / background poller
    pass ``force_refresh=True``.
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
            cached = collector_cache.get_overview(device.hostname, sticky=True)
            if cached is not None:
                results.append(cached)
            else:
                to_fetch.append(device)

    if to_fetch:
        logger.info(
            "Live overview collect for %s device(s) (force_refresh=%s)",
            len(to_fetch),
            force_refresh,
        )
        started = datetime.now(timezone.utc)
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
        elapsed = (datetime.now(timezone.utc) - started).total_seconds()
        logger.info(
            "Live overview collect finished in %.2fs for %s device(s)",
            elapsed,
            len(to_fetch),
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
    """Live (or sticky-cache) switch detail. GUI GETs should use ``get_cached_detail``."""
    cfg = settings or get_settings()
    device = _require_device(hostname)

    if not force_refresh:
        cached = collector_cache.get_detail(device.hostname, sticky=True)
        if cached is not None:
            logger.debug("Cache hit for switch detail %s", device.hostname)
            return cached

    logger.info("Live detail collect starting for %s (force_refresh=%s)", device.hostname, force_refresh)
    started = datetime.now(timezone.utc)
    overview, interfaces = _live_collect_overview_and_interfaces(
        device, device_credentials, cfg
    )
    detail = SwitchDetail(
        **overview.model_dump(),
        interfaces=interfaces,
        recommended_commands=RECOMMENDED_COMMANDS["switch"],
        stale_port_days_threshold=cfg.stale_port_days,
    )
    collector_cache.set_detail(device.hostname, detail, cfg.collector_cache_ttl_seconds)
    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    logger.info(
        "Live detail collect finished for %s in %.2fs (reachable=%s, ports=%s)",
        device.hostname,
        elapsed,
        overview.reachable,
        len(interfaces),
    )
    return detail


def collect_switch_overview(
    device: DeviceInventoryItem,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
    *,
    force_refresh: bool = False,
) -> SwitchOverview:
    """Collect (or return sticky-cached) overview for one inventory device."""
    cfg = settings or get_settings()

    if not force_refresh:
        cached = collector_cache.get_overview(device.hostname, sticky=True)
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
            stale_port_days_threshold=cfg.stale_port_days,
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
        switchport_cmd = (
            "show interface switchport"
            if platform == PlatformType.CISCO_NXOS
            else "show interfaces switchport"
        )
        # All of these are read-only show commands — never configure anything.
        follow_up = [
            status_cmd,
            "show vlan brief",
            switchport_cmd,
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show power inline",
            "show interfaces counters errors",
            "show interfaces status err-disabled",
            "show ip arp",
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
        up_count = sum(
            1
            for i in interfaces
            if i.status == PortOperationalStatus.UP
        )
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

        vlan_by_port = enrich_vlan_map(
            interfaces,
            raw.get("show vlan brief", ""),
            raw.get(switchport_cmd, ""),
        )
        neighbors_by_port = parse_neighbors(
            raw.get("show cdp neighbors detail", ""),
            raw.get("show lldp neighbors detail", ""),
        )
        poe_by_port, poe_used, poe_available = parse_power_inline(
            raw.get("show power inline", "")
        )
        errors_by_port = parse_counters_errors(raw.get("show interfaces counters errors", ""))
        errdisable_reasons = parse_errdisabled_reasons(
            raw.get("show interfaces status err-disabled", "")
        )
        # Optional deeper reason lines from counters/status blobs (still read-only).
        errdisable_reasons.update(
            parse_errdisabled_reasons(raw.get("show interfaces counters errors", ""))
        )

        port_details = [
            _to_port_detail(
                iface,
                device.hostname,
                vlan_by_port,
                neighbors_by_port,
                poe_by_port,
                errors_by_port,
                errdisable_reasons,
                cfg,
            )
            for iface in interfaces
        ]

        err_disabled_count = sum(1 for p in port_details if p.err_disabled)
        stale_port_count = sum(1 for p in port_details if p.is_stale)
        health_warning_count = sum(
            1
            for p in port_details
            if p.health_flags
            or p.high_errors
            or p.duplex_mismatch
            or p.err_disabled
            or p.poe_high_draw
        )
        poe_supported = bool(poe_by_port) or poe_available is not None or poe_used is not None

        # Feed ARP rows into the global tracker index (client-side cache only).
        arp_rows = parse_arp_table(raw.get("show ip arp", ""), device.hostname, device.ip)
        if arp_rows:
            collector_cache.extend_tracker_index(
                [
                    TrackerIndexEntry(
                        hostname=str(row["hostname"] or device.hostname),
                        switch_ip=str(row["switch_ip"] or device.ip),
                        port=row.get("port"),
                        vlan=row.get("vlan"),
                        mac=row.get("mac"),
                        ip=row.get("ip"),
                        source="arp",
                    )
                    for row in arp_rows
                ],
                cfg.collector_cache_ttl_seconds,
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
            poe_supported=poe_supported if poe_supported else None,
            poe_used_watts=poe_used,
            poe_available_watts=poe_available,
            err_disabled_count=err_disabled_count,
            stale_port_count=stale_port_count,
            health_warning_count=health_warning_count,
            error=None,
        )
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


def validate_show_command(command: str) -> str:
    """Normalize and enforce the strict read-only ``show`` safety gate.

    Only single-line commands that begin with ``show`` are accepted. Any
    configure / write / reload / mutating token is rejected immediately.
    """
    cleaned = " ".join(command.strip().split())
    if not cleaned:
        raise CommandRejectedError("Command must not be empty")
    if "\n" in command or "\r" in command or ";" in cleaned:
        raise CommandRejectedError(
            "Command chaining and multi-line input are not allowed"
        )
    normalized = cleaned.lower()
    if not normalized.startswith("show "):
        raise CommandRejectedError(
            "Only read-only 'show' commands are allowed (must begin with 'show ')"
        )
    if not _is_read_only(cleaned):
        raise CommandRejectedError(
            "Command blocked: configure, write, reload, and other mutating "
            "operations are permanently prohibited"
        )
    return cleaned


def execute_show_command(
    hostname: str,
    command: str,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
) -> ExecCommandResponse:
    """SSH to one switch and run a single validated read-only ``show`` command."""
    cfg = settings or get_settings()
    device = _require_device(hostname)
    safe_command = validate_show_command(command)
    executed_at = datetime.now(timezone.utc)

    try:
        outputs = _run_commands(device, [safe_command], cfg, device_credentials)
    except CollectorError:
        raise
    except NetmikoAuthenticationException as exc:
        return ExecCommandResponse(
            hostname=device.hostname,
            command=safe_command,
            output="",
            success=False,
            error=f"Authentication failed: {exc}",
            executed_at=executed_at,
        )
    except NetmikoTimeoutException as exc:
        return ExecCommandResponse(
            hostname=device.hostname,
            command=safe_command,
            output="",
            success=False,
            error=f"Connection timed out: {exc}",
            executed_at=executed_at,
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "exec-command failed on %s (%s): %s — %s",
            device.hostname,
            safe_command,
            exc.__class__.__name__,
            exc,
        )
        return ExecCommandResponse(
            hostname=device.hostname,
            command=safe_command,
            output="",
            success=False,
            error=f"SSH execution failed: {exc.__class__.__name__}: {exc}",
            executed_at=executed_at,
        )

    output = outputs.get(safe_command, "")
    if not output.strip():
        output = "(no output from device)"

    return ExecCommandResponse(
        hostname=device.hostname,
        command=safe_command,
        output=output,
        success=True,
        error=None,
        executed_at=executed_at,
    )


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
            stale_port_days_threshold=cfg.stale_port_days,
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


# ---------------------------------------------------------------------------
# VLAN enrichment + CDP/LLDP neighbors (read-only show output only)
# ---------------------------------------------------------------------------

# Long interface type → short prefix used for matching CDP/LLDP local ports.
_IFACE_LONG_TO_SHORT: tuple[tuple[str, str], ...] = (
    ("tengigabitethernet", "te"),
    ("twentyfivegige", "twe"),
    ("fortygigabitethernet", "fo"),
    ("hundredgige", "hu"),
    ("appgigabitethernet", "ap"),
    ("gigabitethernet", "gi"),
    ("fastethernet", "fa"),
    ("ethernet", "eth"),
    ("port-channel", "po"),
    ("mgmt", "mgmt"),
    ("vlan", "vl"),
)


def normalize_iface_key(name: str | None) -> str:
    """Canonical key so Gi1/0/1 and GigabitEthernet1/0/1 map together."""
    if not name:
        return ""
    raw = name.strip().lower().replace(" ", "")
    # Strip trailing comma / period from CDP "Interface: Gi1/0/1," style.
    raw = raw.rstrip(".,;")
    for long_name, short in _IFACE_LONG_TO_SHORT:
        if raw.startswith(long_name):
            return short + raw[len(long_name) :]
    return raw


def enrich_vlan_map(
    interfaces: list[InterfaceStatus],
    vlan_brief_text: str,
    switchport_text: str,
) -> dict[str, str]:
    """
    Build port → VLAN label (access ID, trunk, routed).

    Primary source: show interfaces status. Fallbacks / refinements from
    show interfaces switchport and show vlan brief — all read-only.
    """
    result: dict[str, str] = {}
    for iface in interfaces:
        key = normalize_iface_key(iface.port)
        if iface.vlan:
            result[key] = iface.vlan

    switchport_vlans = parse_switchport_vlans(switchport_text)
    for key, vlan in switchport_vlans.items():
        # Prefer explicit access/trunk from switchport when status was empty.
        if key not in result or not result[key]:
            result[key] = vlan
        elif result[key].lower() == "trunk" and vlan.lower().startswith("trunk"):
            result[key] = vlan  # e.g. trunk (native 1)

    # show vlan brief lists member ports for access VLANs — fill gaps only.
    brief_vlans = parse_vlan_brief_port_map(vlan_brief_text)
    for key, vlan in brief_vlans.items():
        if key not in result or not result[key]:
            result[key] = vlan

    return result


def parse_switchport_vlans(output: str) -> dict[str, str]:
    """Parse `show interfaces switchport` / `show interface switchport`."""
    text = normalize_cli_text(output)
    if _is_cli_error(text) or not text.strip():
        return {}

    result: dict[str, str] = {}
    current_port: str | None = None
    mode: str | None = None
    access_vlan: str | None = None
    native_vlan: str | None = None

    def _flush() -> None:
        nonlocal current_port, mode, access_vlan, native_vlan
        if not current_port:
            return
        key = normalize_iface_key(current_port)
        mode_l = (mode or "").lower()
        if "trunk" in mode_l:
            label = f"trunk (native {native_vlan})" if native_vlan else "trunk"
        elif "access" in mode_l or access_vlan:
            label = access_vlan or "1"
        elif "routed" in mode_l or "dynamic" in mode_l and not access_vlan:
            label = "routed" if "routed" in mode_l else (access_vlan or mode or "")
        else:
            label = access_vlan or native_vlan or mode or ""
        if key and label:
            result[key] = label
        current_port = None
        mode = None
        access_vlan = None
        native_vlan = None

    name_re = re.compile(
        r"^Name:\s+(\S+)",
        re.IGNORECASE,
    )
    # NX-OS sometimes: "Interface Name: Ethernet1/1"
    name_re_nx = re.compile(
        r"^Interface\s+Name:\s+(\S+)",
        re.IGNORECASE,
    )
    mode_re = re.compile(
        r"^Administrative Mode:\s+(.+)$",
        re.IGNORECASE,
    )
    # Operational Mode is a good fallback when admin mode is dynamic
    op_mode_re = re.compile(
        r"^Operational Mode:\s+(.+)$",
        re.IGNORECASE,
    )
    access_re = re.compile(
        r"^Access Mode VLAN:\s+(\d+)",
        re.IGNORECASE,
    )
    native_re = re.compile(
        r"^Trunking Native Mode VLAN:\s+(\d+)",
        re.IGNORECASE,
    )
    # NX-OS variants
    access_re_nx = re.compile(
        r"^Access\s+Vlan:\s+(\d+)",
        re.IGNORECASE,
    )
    native_re_nx = re.compile(
        r"^Native\s+Vlan:\s+(\d+)",
        re.IGNORECASE,
    )

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        match = name_re.match(stripped) or name_re_nx.match(stripped)
        if match:
            _flush()
            current_port = match.group(1)
            continue
        if current_port is None:
            continue
        match = mode_re.match(stripped)
        if match:
            mode = match.group(1).strip()
            continue
        match = op_mode_re.match(stripped)
        if match and (not mode or "dynamic" in mode.lower()):
            mode = match.group(1).strip()
            continue
        match = access_re.match(stripped) or access_re_nx.match(stripped)
        if match:
            access_vlan = match.group(1)
            continue
        match = native_re.match(stripped) or native_re_nx.match(stripped)
        if match:
            native_vlan = match.group(1)
            continue
    _flush()
    return result


def parse_vlan_brief_port_map(output: str) -> dict[str, str]:
    """Map member ports → VLAN ID from `show vlan brief` (access membership)."""
    text = normalize_cli_text(output)
    if _is_cli_error(text) or not text.strip():
        return {}

    result: dict[str, str] = {}
    # Lines like: 10   DATA VLAN   active   Gi1/0/1, Gi1/0/2, Gi1/0/5
    # Continuation lines may be indented port lists only.
    entry_re = re.compile(
        r"^(\d+)\s+(.+?)\s+(active|suspend|act/unsup|act/lshut|act/isolate)\s*(.*)$",
        re.IGNORECASE,
    )
    current_vlan: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("vlan") or stripped.startswith("---"):
            continue
        match = entry_re.match(stripped)
        if match:
            current_vlan = match.group(1)
            ports_blob = match.group(4)
        elif current_vlan and not stripped[:1].isdigit():
            ports_blob = stripped
        else:
            continue
        for token in re.split(r"[,\s]+", ports_blob):
            token = token.strip().rstrip(",")
            if not token:
                continue
            if _looks_like_interface(token):
                key = normalize_iface_key(token)
                # Do not overwrite a prior membership; first VLAN wins for multi-listed edge cases.
                result.setdefault(key, current_vlan)
    return result


def parse_neighbors(
    cdp_detail: str,
    lldp_detail: str,
) -> dict[str, dict[str, str | None]]:
    """
    Parse CDP then LLDP detail. CDP wins when both advertise on the same local port.
    Returns map: normalized local port → neighbor fields.
    """
    result: dict[str, dict[str, str | None]] = {}
    for entry in parse_cdp_neighbors_detail(cdp_detail):
        key = normalize_iface_key(entry.get("local_port"))
        if key:
            result[key] = entry
    for entry in parse_lldp_neighbors_detail(lldp_detail):
        key = normalize_iface_key(entry.get("local_port"))
        if key and key not in result:
            result[key] = entry
    return result


def parse_cdp_neighbors_detail(output: str) -> list[dict[str, str | None]]:
    """Parse `show cdp neighbors detail` (IOS / NX-OS)."""
    text = normalize_cli_text(output)
    if _is_cli_error(text) or not text.strip():
        return []
    # Skip empty / disabled CDP responses.
    lowered = text.lower()
    if "cdp is not enabled" in lowered or "invalid command" in lowered:
        return []

    entries: list[dict[str, str | None]] = []
    blocks = re.split(r"(?m)^-+\s*$", text)
    for block in blocks:
        block = block.strip()
        if not block or "device id" not in block.lower():
            continue
        device_id = _re_first(
            r"Device ID:\s*(.+)",
            block,
        )
        local_port = _re_first(
            r"Interface:\s*([^,\n]+)",
            block,
        )
        remote_port = _re_first(
            r"Port ID\s*\(outgoing port\):\s*(.+)",
            block,
        )
        if not remote_port:
            remote_port = _re_first(r"Port ID:\s*(.+)", block)
        platform = _re_first(r"Platform:\s*([^,\n]+)", block)
        capabilities = _re_first(r"Capabilities:\s*(.+)", block)
        ip_addr = _re_first(
            r"(?:IP|IPv4)\s+[Aa]ddress:\s*([0-9.]+)",
            block,
        )
        if not ip_addr:
            ip_addr = _re_first(
                r"Entry address\(es\):.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
                block,
                flags=re.IGNORECASE | re.DOTALL,
            )
        if not local_port and not device_id:
            continue
        entries.append(
            {
                "protocol": "cdp",
                "local_port": (local_port or "").strip(),
                "neighbor_hostname": (device_id or "").strip() or None,
                "neighbor_ip": (ip_addr or "").strip() or None,
                "neighbor_platform": (platform or "").strip() or None,
                "neighbor_port": (remote_port or "").strip() or None,
                "capabilities": (capabilities or "").strip() or None,
            }
        )
    return entries


def parse_lldp_neighbors_detail(output: str) -> list[dict[str, str | None]]:
    """Parse `show lldp neighbors detail` (IOS / NX-OS)."""
    text = normalize_cli_text(output)
    if _is_cli_error(text) or not text.strip():
        return []
    lowered = text.lower()
    if "lldp is not enabled" in lowered or "invalid input" in lowered:
        return []

    entries: list[dict[str, str | None]] = []
    # IOS uses ---- separators; also split on "Local Intf:" / "Local Port" starts.
    blocks = re.split(r"(?m)^(?:-+|\s*Local (?:Intf|Port)\s*:)", text)
    # Re-attach Local Intf for blocks that lost the header via split.
    # Simpler approach: find all Local Intf blocks with a dedicated regex walk.
    local_starts = list(
        re.finditer(
            r"(?im)^(?:Local Intf|Local Port|Interface):\s*(\S+)",
            text,
        )
    )
    if not local_starts:
        # NX-OS sometimes: "Port id: Ethernet1/1" as local in chassis blocks —
        # fall back to Chassis/System Name blocks split by ----
        for block in re.split(r"(?m)^-+\s*$", text):
            block = block.strip()
            if not block or "system name" not in block.lower():
                continue
            entries.extend(_parse_one_lldp_block(block, local_port=None))
        return entries

    for idx, match in enumerate(local_starts):
        start = match.start()
        end = local_starts[idx + 1].start() if idx + 1 < len(local_starts) else len(text)
        block = text[start:end]
        local_port = match.group(1).strip()
        entries.extend(_parse_one_lldp_block(block, local_port=local_port))
    return entries


def _parse_one_lldp_block(
    block: str,
    local_port: str | None,
) -> list[dict[str, str | None]]:
    system_name = _re_first(r"System Name:\s*(.+)", block)
    # Some stacks put hostname only in System Description first token.
    if not system_name:
        system_name = _re_first(r"System Description:\s*(\S+)", block)
    platform = _re_first(r"System Description:\s*(.+)", block)
    if platform and len(platform) > 80:
        platform = platform[:80].rstrip() + "…"
    remote_port = _re_first(r"Port id:\s*(.+)", block)
    if not remote_port:
        remote_port = _re_first(r"Port Description:\s*(.+)", block)
    ip_addr = _re_first(
        r"(?:IP|IPv4|Management address):\s*([0-9.]+)",
        block,
        flags=re.IGNORECASE,
    )
    if not ip_addr:
        ip_addr = _re_first(
            r"Management Addresses:.*?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
            block,
            flags=re.IGNORECASE | re.DOTALL,
        )
    # If local_port not provided, try Chassis-style NX-OS "Local Port id"
    if not local_port:
        local_port = _re_first(r"Local Port id:\s*(\S+)", block)
    if not local_port and not system_name:
        return []
    return [
        {
            "protocol": "lldp",
            "local_port": (local_port or "").strip(),
            "neighbor_hostname": (system_name or "").strip() or None,
            "neighbor_ip": (ip_addr or "").strip() or None,
            "neighbor_platform": (platform or "").strip() or None,
            "neighbor_port": (remote_port or "").strip() or None,
            "capabilities": None,
        }
    ]


def _re_first(pattern: str, text: str, flags: int = re.IGNORECASE) -> str | None:
    match = re.search(pattern, text, flags)
    if not match:
        return None
    return match.group(1).strip()


def _format_connected_device(neighbor: dict[str, str | None]) -> str | None:
    hostname = neighbor.get("neighbor_hostname")
    platform = neighbor.get("neighbor_platform")
    ip_addr = neighbor.get("neighbor_ip")
    protocol = neighbor.get("protocol")
    remote_port = neighbor.get("neighbor_port")
    if not any((hostname, platform, ip_addr)):
        return None
    parts: list[str] = []
    if hostname:
        parts.append(hostname)
    detail_bits: list[str] = []
    if platform:
        detail_bits.append(platform)
    if ip_addr:
        detail_bits.append(ip_addr)
    if remote_port:
        detail_bits.append(f"port {remote_port}")
    if detail_bits:
        parts.append(f"({', '.join(detail_bits)})")
    if protocol:
        parts.append(f"via {protocol.upper()}")
    return " ".join(parts)


def _to_port_detail(
    iface: InterfaceStatus,
    hostname: str,
    vlan_by_port: dict[str, str],
    neighbors_by_port: dict[str, dict[str, str | None]],
    poe_by_port: dict[str, dict[str, Any]],
    errors_by_port: dict[str, dict[str, int]],
    errdisable_reasons: dict[str, str],
    cfg: Settings,
) -> PortDetail:
    key = normalize_iface_key(iface.port)
    vlan = vlan_by_port.get(key) or iface.vlan
    neighbor = neighbors_by_port.get(key)
    protocol_raw = neighbor.get("protocol") if neighbor else None
    protocol: Literal["cdp", "lldp"] | None = (
        protocol_raw if protocol_raw in ("cdp", "lldp") else None
    )

    # Remap status if the raw status token indicated err-disabled.
    status = iface.status
    err_reason = (
        errdisable_reasons.get(iface.port)
        or errdisable_reasons.get(key)
        or next(
            (
                reason
                for raw_port, reason in errdisable_reasons.items()
                if normalize_iface_key(raw_port) == key
            ),
            None,
        )
    )
    if err_reason or status == PortOperationalStatus.ERR_DISABLED:
        status = PortOperationalStatus.ERR_DISABLED

    device_type = None
    if neighbor:
        device_type = classify_neighbor(
            neighbor.get("neighbor_hostname"),
            neighbor.get("neighbor_platform"),
            neighbor.get("capabilities"),
        )

    poe = None
    for raw_port, payload in poe_by_port.items():
        if normalize_iface_key(raw_port) == key:
            poe = payload
            break
    poe_watts = float(poe["poe_watts"]) if poe and poe.get("poe_watts") is not None else None
    poe_max = float(poe["poe_max_watts"]) if poe and poe.get("poe_max_watts") is not None else None
    poe_high = bool(
        poe_watts is not None
        and poe_max
        and poe_max > 0
        and (poe_watts / poe_max) >= cfg.poe_high_draw_ratio
    )

    counters = None
    for raw_port, payload in errors_by_port.items():
        if normalize_iface_key(raw_port) == key:
            counters = payload
            break

    duplex_mismatch = detect_duplex_mismatch(iface.duplex, iface.speed, status)
    high_errors = is_high_error_rate(counters)

    is_link_down = status in {
        PortOperationalStatus.DOWN,
        PortOperationalStatus.ADMIN_DOWN,
        PortOperationalStatus.ERR_DISABLED,
    }
    down_since = collector_cache.note_port_link_state(hostname, iface.port, is_link_down)
    stale_days: int | None = None
    is_stale = False
    if down_since is not None:
        stale_days = max(0, (datetime.now(timezone.utc) - down_since).days)
        is_stale = stale_days >= cfg.stale_port_days

    health_flags: list[str] = []
    if status == PortOperationalStatus.ERR_DISABLED:
        health_flags.append(f"err-disabled:{err_reason or 'unknown'}")
    if duplex_mismatch:
        health_flags.append("duplex-mismatch")
    if high_errors:
        health_flags.append("high-errors")
    if poe_high:
        health_flags.append("poe-high-draw")
    if is_stale:
        health_flags.append(f"stale:{stale_days}d")

    return PortDetail(
        port=iface.port,
        status=status,
        vlan=vlan,
        duplex=iface.duplex,
        speed=iface.speed,
        type=iface.type,
        description=iface.description,
        trust_level=iface.trust_level,
        neighbor_hostname=neighbor.get("neighbor_hostname") if neighbor else None,
        neighbor_ip=neighbor.get("neighbor_ip") if neighbor else None,
        neighbor_platform=neighbor.get("neighbor_platform") if neighbor else None,
        neighbor_port=neighbor.get("neighbor_port") if neighbor else None,
        neighbor_protocol=protocol,
        neighbor_device_type=device_type,
        connected_device=_format_connected_device(neighbor) if neighbor else None,
        poe_status=str(poe["poe_status"]) if poe and poe.get("poe_status") else None,
        poe_watts=poe_watts,
        poe_class=str(poe["poe_class"]) if poe and poe.get("poe_class") else None,
        poe_max_watts=poe_max,
        poe_high_draw=poe_high,
        err_disabled=status == PortOperationalStatus.ERR_DISABLED,
        err_disabled_reason=err_reason if status == PortOperationalStatus.ERR_DISABLED else None,
        input_errors=counters.get("input_errors") if counters else None,
        output_errors=counters.get("output_errors") if counters else None,
        crc_errors=counters.get("crc_errors") if counters else None,
        frame_errors=counters.get("frame_errors") if counters else None,
        collisions=counters.get("collisions") if counters else None,
        duplex_mismatch=duplex_mismatch,
        high_errors=high_errors,
        down_since=down_since,
        stale_days=stale_days,
        is_stale=is_stale,
        health_flags=health_flags,
    )


def _map_port_status(raw: str) -> PortOperationalStatus:
    value = raw.lower().strip()
    if value in {"connected", "up"}:
        return PortOperationalStatus.UP
    if value in {"disabled", "admin-down", "administratively down"}:
        return PortOperationalStatus.ADMIN_DOWN
    if value in {"err-disabled", "errdisabled", "err-disable", "error disabled"}:
        return PortOperationalStatus.ERR_DISABLED
    if value in {
        "notconnect",
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
