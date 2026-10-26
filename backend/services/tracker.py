"""Global IP / MAC / hostname tracker — read-only correlation across the fleet.

Uses cached ARP/neighbor bindings when warm, then live ``show mac address-table``
and ``show ip arp`` (never configuration commands).
"""

from __future__ import annotations

import logging
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Literal

from backend.auth.session_store import DeviceCredentials
from backend.config import Settings, get_settings
from backend.models.schemas import DeviceInventoryItem, TrackerHit, TrackerSearchResponse
from backend.services.collector_cache import collector_cache
from backend.services.cisco_collector import (
    _friendly_error,
    _run_commands,
    _to_cisco_mac,
    parse_mac_table,
)
from backend.services.inventory import load_inventory
from backend.services.poe_health import parse_arp_table

logger = logging.getLogger(__name__)

QueryType = Literal["ip", "mac", "hostname", "neighbor", "unknown"]


def detect_query_type(query: str) -> QueryType:
    q = query.strip()
    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", q):
        return "ip"
    hex_only = re.sub(r"[.\-:\s]", "", q.lower())
    if len(hex_only) >= 4 and re.fullmatch(r"[0-9a-f]+", hex_only):
        return "mac"
    if re.search(r"[a-zA-Z]", q):
        return "hostname"
    return "unknown"


def global_tracker_search(
    query: str,
    device_credentials: DeviceCredentials,
    hostname: str | None = None,
    settings: Settings | None = None,
) -> TrackerSearchResponse:
    """Search MAC / ARP / neighbor bindings across inventory (read-only)."""
    cfg = settings or get_settings()
    q = query.strip()
    qtype = detect_query_type(q)
    devices = load_inventory()
    if hostname:
        devices = [d for d in devices if d.hostname.lower() == hostname.lower()]

    hits: list[TrackerHit] = []
    errors: list[str] = []
    failed = 0

    # 1) Fast path: in-memory cache (neighbors + ARP from recent collects).
    hits.extend(_search_cache(q, qtype, hostname))

    # 2) Live path: parallel MAC + ARP show commands on each device.
    if devices:
        workers = max(1, min(cfg.collector_max_workers, len(devices)))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(
                    _live_search_device,
                    device,
                    q,
                    qtype,
                    device_credentials,
                    cfg,
                ): device
                for device in devices
            }
            for future in as_completed(futures):
                device = futures[future]
                try:
                    hits.extend(future.result())
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    errors.append(f"{device.hostname}: {_friendly_error(exc)}")
                    logger.warning("Tracker search failed on %s: %s", device.hostname, exc)

    resolved_type: QueryType = qtype
    if resolved_type == "unknown" and re.search(r"[A-Za-z]", q):
        resolved_type = "hostname"

    return TrackerSearchResponse(
        query=q,
        query_type=resolved_type,
        hits=_dedupe_hits(hits),
        devices_queried=len(devices),
        devices_failed=failed,
        errors=errors,
        searched_at=datetime.now(timezone.utc),
    )


def _search_cache(query: str, qtype: QueryType, hostname: str | None) -> list[TrackerHit]:
    hits: list[TrackerHit] = []
    needle = query.strip().lower()
    mac_needle = re.sub(r"[.\-:\s]", "", needle)

    for row in collector_cache.get_tracker_index():
        if hostname and row.hostname.lower() != hostname.lower():
            continue
        matched = False
        if qtype == "ip" and row.ip and row.ip.lower() == needle:
            matched = True
        elif qtype == "mac" and row.mac:
            row_mac = re.sub(r"[.\-:\s]", "", row.mac.lower())
            if mac_needle and mac_needle in row_mac:
                matched = True
        elif qtype in {"hostname", "neighbor", "unknown"}:
            if row.neighbor_hostname and needle in row.neighbor_hostname.lower():
                matched = True
            elif row.ip and needle == row.ip.lower():
                matched = True
        if not matched:
            continue
        source: Literal["mac", "arp", "neighbor", "cache"]
        if row.source in {"mac", "arp", "neighbor", "cache"}:
            source = row.source  # type: ignore[assignment]
        else:
            source = "cache"
        hits.append(
            TrackerHit(
                query_type=qtype if qtype != "unknown" else "neighbor",
                hostname=row.hostname,
                switch_ip=row.switch_ip,
                port=row.port,
                vlan=row.vlan,
                mac=row.mac,
                ip=row.ip,
                neighbor_hostname=row.neighbor_hostname,
                source=source,
                detail="Cached binding",
            )
        )

    for detail in collector_cache.list_details():
        if hostname and detail.hostname.lower() != hostname.lower():
            continue
        for iface in detail.interfaces:
            nb = (iface.neighbor_hostname or "").lower()
            nip = (iface.neighbor_ip or "").lower()
            if qtype == "ip" and nip == needle:
                pass
            elif qtype in {"hostname", "neighbor", "unknown"} and needle and needle in nb:
                pass
            else:
                continue
            hits.append(
                TrackerHit(
                    query_type="neighbor",
                    hostname=detail.hostname,
                    switch_ip=detail.ip,
                    port=iface.port,
                    vlan=iface.vlan,
                    mac=None,
                    ip=iface.neighbor_ip,
                    neighbor_hostname=iface.neighbor_hostname,
                    source="neighbor",
                    detail=iface.connected_device,
                )
            )
    return hits


def _live_search_device(
    device: DeviceInventoryItem,
    query: str,
    qtype: QueryType,
    device_credentials: DeviceCredentials,
    cfg: Settings,
) -> list[TrackerHit]:
    hits: list[TrackerHit] = []
    commands: list[str] = []
    mac_filter: str | None = None

    if qtype == "mac":
        mac_filter = re.sub(r"[.\-:\s]", "", query.lower())
        cisco_mac = _to_cisco_mac(mac_filter)
        commands.extend(
            [
                f"show mac address-table | include {cisco_mac}",
                "show mac address-table",
                "show ip arp",
            ]
        )
    elif qtype == "ip":
        commands.extend(
            [
                f"show ip arp | include {query}",
                "show ip arp",
                "show mac address-table",
            ]
        )
    else:
        # Hostname searches rely primarily on CDP/LLDP cache; ARP/MAC still collected lightly.
        commands.extend(["show ip arp", "show mac address-table"])

    raw = _run_commands(device, commands, cfg, device_credentials)

    mac_text = ""
    for key, value in raw.items():
        if "mac address-table" in key and value:
            mac_text = value

    if qtype == "mac" and mac_filter:
        for hit in parse_mac_table(mac_text, device.hostname, device.ip):
            mac_norm = re.sub(r"[.\-:\s]", "", hit.mac.lower())
            if mac_filter not in mac_norm:
                continue
            hits.append(
                TrackerHit(
                    query_type="mac",
                    hostname=device.hostname,
                    switch_ip=device.ip,
                    port=hit.port,
                    vlan=hit.vlan,
                    mac=hit.mac,
                    ip=None,
                    source="mac",
                )
            )

    arp_text = ""
    for key, value in raw.items():
        if "arp" in key and value:
            arp_text = value
            break

    for row in parse_arp_table(arp_text, device.hostname, device.ip):
        ip_addr = (row.get("ip") or "").lower()
        mac = (row.get("mac") or "").lower()
        mac_norm = re.sub(r"[.\-:\s]", "", mac)
        if qtype == "ip" and ip_addr != query.lower():
            continue
        if qtype == "mac" and mac_filter and mac_filter not in mac_norm:
            continue
        if qtype in {"hostname", "unknown"}:
            if query.lower() not in ip_addr and query.lower() not in mac_norm:
                continue

        access_port = row.get("port")
        vlan = row.get("vlan")
        if mac_text and mac_norm:
            for mhit in parse_mac_table(mac_text, device.hostname, device.ip):
                if re.sub(r"[.\-:\s]", "", mhit.mac.lower()) == mac_norm:
                    access_port = mhit.port or access_port
                    vlan = mhit.vlan or vlan
                    break

        hits.append(
            TrackerHit(
                query_type="ip" if qtype == "ip" else ("mac" if qtype == "mac" else "hostname"),
                hostname=device.hostname,
                switch_ip=device.ip,
                port=access_port,
                vlan=vlan,
                mac=mac,
                ip=row.get("ip"),
                source="arp",
            )
        )
    return hits


def _dedupe_hits(hits: list[TrackerHit]) -> list[TrackerHit]:
    seen: set[tuple[str, str, str, str, str]] = set()
    out: list[TrackerHit] = []
    for hit in hits:
        key = (
            hit.hostname.lower(),
            (hit.port or "").lower(),
            (hit.mac or "").lower(),
            (hit.ip or "").lower(),
            (hit.neighbor_hostname or "").lower(),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(hit)
    out.sort(key=lambda h: (h.hostname.lower(), h.port or "", h.ip or ""))
    return out
