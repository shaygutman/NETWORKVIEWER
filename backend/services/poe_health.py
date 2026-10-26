"""Read-only PoE, neighbor classification, and port-health parsers.

All helpers operate on CLI ``show`` output already collected by the SSH
collector. Nothing in this module sends commands or changes device state.
"""

from __future__ import annotations

import re
from typing import Any

from backend.models.schemas import NeighborDeviceType, PortOperationalStatus


def classify_neighbor(
    hostname: str | None,
    platform: str | None,
    capabilities: str | None = None,
) -> NeighborDeviceType:
    """Classify CDP/LLDP neighbor into switch / phone / AP / server / host."""
    blob = " ".join(
        part for part in ((hostname or ""), (platform or ""), (capabilities or "")) if part
    ).lower()
    if not blob.strip():
        return NeighborDeviceType.UNKNOWN

    if hostname and hostname.upper().startswith("SEP"):
        return NeighborDeviceType.PHONE
    if re.search(r"\bsep[0-9a-f]{12}\b", blob) or "ip phone" in blob or "cisco ip phone" in blob:
        return NeighborDeviceType.PHONE
    if "phone" in blob and "microphone" not in blob:
        return NeighborDeviceType.PHONE

    if any(
        token in blob
        for token in (
            "access point",
            "air-",
            "aironet",
            "trans-bridge",
            "cw916",
            "c9120",
            "c9115",
            "c9130",
            "ap2802",
            "ap3802",
            "ap4800",
            "catalyst 91",
        )
    ) or re.search(r"\bap[-_]?\d", blob):
        return NeighborDeviceType.AP

    if any(
        token in blob
        for token in (
            "dell",
            "proliant",
            "hpe ",
            "hp ",
            "idrac",
            "ilo ",
            "ilo-",
            "supermicro",
            "poweredge",
        )
    ):
        return NeighborDeviceType.SERVER

    if any(
        token in blob
        for token in (
            "switch",
            "nexus",
            "catalyst",
            "ws-c",
            "c9200",
            "c9300",
            "c9400",
            "c9500",
            "ie-3",
            "ie-4",
            "router",
            "asr",
            "isr",
        )
    ):
        return NeighborDeviceType.SWITCH

    if capabilities:
        caps = capabilities.lower()
        if "phone" in caps:
            return NeighborDeviceType.PHONE
        if "trans-bridge" in caps or "igmp" in caps and "switch" in caps:
            return NeighborDeviceType.AP
        if "switch" in caps:
            return NeighborDeviceType.SWITCH

    return NeighborDeviceType.HOST


def parse_power_inline(output: str) -> tuple[dict[str, dict[str, Any]], float | None, float | None]:
    """
    Parse ``show power inline`` (IOS / IOS-XE) and NX-OS equivalents.

    Returns (per_port_map, used_watts, available_watts).
    per_port_map keys are raw interface names (normalize later).
    """
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        return {}, None, None
    lowered = text.lower()
    if any(
        token in lowered
        for token in (
            "invalid input",
            "invalid command",
            "ambiguous command",
            "power inline not supported",
            "poe not supported",
        )
    ):
        return {}, None, None

    used: float | None = None
    available: float | None = None

    # Available:370(w)  Used:45.4(w)  Remaining:324.6(w)
    m_avail = re.search(r"Available\s*:\s*([\d.]+)\s*\(?w\)?", text, re.I)
    m_used = re.search(r"Used\s*:\s*([\d.]+)\s*\(?w\)?", text, re.I)
    if m_avail:
        available = float(m_avail.group(1))
    if m_used:
        used = float(m_used.group(1))
    # NX-OS / alternate summaries
    if available is None:
        m = re.search(r"Total\s+Power\s+Available\s*[:=]\s*([\d.]+)", text, re.I)
        if m:
            available = float(m.group(1))
    if used is None:
        m = re.search(r"Total\s+Power\s+Drawn\s*[:=]\s*([\d.]+)", text, re.I)
        if m:
            used = float(m.group(1))

    ports: dict[str, dict[str, Any]] = {}
    # Gi1/0/1   auto   on   6.3   IP Phone …   2   30.0
    row_re = re.compile(
        r"^(?P<port>(?:Gi|Te|Fa|Eth|Ethernet|GigabitEthernet|TenGigabitEthernet|Tw)\S*)\s+"
        r"(?P<admin>\S+)\s+"
        r"(?P<oper>\S+)\s+"
        r"(?P<power>[\d.]+)\s+"
        r"(?P<device>.+?)\s+"
        r"(?P<cls>\S+)\s+"
        r"(?P<max>[\d.]+)\s*$",
        re.IGNORECASE,
    )
    # Simpler row without device name columns well-aligned
    row_re_loose = re.compile(
        r"^(?P<port>(?:Gi|Te|Fa|Eth|Ethernet|GigabitEthernet|TenGigabitEthernet)\S*)\s+"
        r"(?P<admin>auto|off|static|n/a)\s+"
        r"(?P<oper>on|off|faulty|deny|err-disable|errdisable|power-deny|n/a)\s+"
        r"(?P<power>[\d.]+)",
        re.IGNORECASE,
    )

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("interface"):
            continue
        match = row_re.match(stripped)
        if match:
            ports[match.group("port")] = {
                "poe_admin": match.group("admin"),
                "poe_status": match.group("oper").lower(),
                "poe_watts": float(match.group("power")),
                "poe_device": match.group("device").strip(),
                "poe_class": match.group("cls"),
                "poe_max_watts": float(match.group("max")),
            }
            continue
        match = row_re_loose.match(stripped)
        if match:
            rest = stripped[match.end() :].strip().split()
            poe_class = rest[-2] if len(rest) >= 2 else None
            poe_max = None
            if rest:
                try:
                    poe_max = float(rest[-1])
                    poe_class = rest[-2] if len(rest) >= 2 else poe_class
                except ValueError:
                    poe_max = None
            ports[match.group("port")] = {
                "poe_admin": match.group("admin"),
                "poe_status": match.group("oper").lower(),
                "poe_watts": float(match.group("power")),
                "poe_device": None,
                "poe_class": poe_class,
                "poe_max_watts": poe_max,
            }

    if used is None and ports:
        used = round(sum(float(p["poe_watts"]) for p in ports.values()), 1)

    return ports, used, available


def parse_counters_errors(output: str) -> dict[str, dict[str, int]]:
    """Parse ``show interfaces counters errors`` into per-port error counters."""
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip() or "invalid" in text.lower()[:80]:
        return {}

    results: dict[str, dict[str, int]] = {}
    # Port      Align-Err  FCS-Err    Xmit-Err  Rcv-Err   UnderSize  OutDiscards
    # Or: Port  Align-Err FCS-Err Xmit-Err Rcv-Err UnderSize OutDiscards Single-Col Multi-Col …
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith("port") or stripped.startswith("---"):
            continue
        parts = stripped.split()
        if len(parts) < 5:
            continue
        port = parts[0]
        if not re.match(r"^[A-Za-z]", port):
            continue
        nums: list[int] = []
        for token in parts[1:]:
            token = token.replace(",", "")
            if re.fullmatch(r"\d+", token):
                nums.append(int(token))
            else:
                break
        if len(nums) < 4:
            continue
        # Common IOS layout: Align FCS Xmit Rcv UnderSize OutDisc [Single Multi Late Excess ...]
        align, fcs, xmit, rcv = nums[0], nums[1], nums[2], nums[3]
        collisions = sum(nums[6:10]) if len(nums) >= 10 else (nums[6] if len(nums) > 6 else 0)
        results[port] = {
            "crc_errors": fcs,
            "frame_errors": align,
            "input_errors": rcv + fcs + align,
            "output_errors": xmit,
            "collisions": collisions,
        }
    return results


def parse_errdisabled_reasons(output: str) -> dict[str, str]:
    """
    Best-effort reason extraction from err-disabled related show output / logging snippets.

    Accepts ``show interfaces status err-disabled`` (ports only) or mixed text that
    includes ``ERR_DISABLE`` / ``err-disabled due to …`` lines.
    """
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    reasons: dict[str, str] = {}
    if not text.strip():
        return reasons

    # %PM-4-ERR_DISABLE: bpduguard error detected on Gi1/0/5, putting Gi1/0/5 in err-disable state
    for match in re.finditer(
        r"ERR_DISABLE:\s*(\S+)\s+error detected on\s+(\S+)",
        text,
        re.IGNORECASE,
    ):
        reasons[match.group(2).rstrip(",")] = match.group(1).lower()

    # error disabled due to bpduguard / port-security / …
    for match in re.finditer(
        r"(\S+)\s+.*?err(?:or)?[\s-]*disabled due to\s+([a-z0-9\-_]+)",
        text,
        re.IGNORECASE,
    ):
        reasons[match.group(1)] = match.group(2).lower()

    # show interfaces status err-disabled — mark presence without specific cause
    for line in text.splitlines():
        stripped = line.strip()
        if "err-disabled" not in stripped.lower() and "errdisabled" not in stripped.lower():
            continue
        port = stripped.split()[0] if stripped.split() else ""
        if port and re.match(r"^[A-Za-z]", port) and port.lower() not in {"port", "interface"}:
            reasons.setdefault(port, "err-disabled")

    return reasons


def detect_duplex_mismatch(
    duplex: str | None,
    speed: str | None,
    status: PortOperationalStatus,
) -> bool:
    """Flag half-duplex on an up / high-speed link as likely mismatch risk."""
    if status != PortOperationalStatus.UP:
        return False
    dup = (duplex or "").lower()
    if "half" not in dup:
        return False
    spd = (speed or "").lower().replace("a-", "").replace(" ", "")
    if spd in {"10", "auto", ""}:
        # 10H is common on legacy gear — still warn lightly by returning True for visibility
        return True
    return True


def is_high_error_rate(counters: dict[str, int] | None, threshold: int = 100) -> bool:
    if not counters:
        return False
    return any(
        int(counters.get(key, 0) or 0) >= threshold
        for key in ("crc_errors", "input_errors", "output_errors", "frame_errors")
    )


def parse_arp_table(output: str, hostname: str, switch_ip: str) -> list[dict[str, str | None]]:
    """Parse ``show ip arp`` / ``show ip arp vrf all`` style tables (read-only)."""
    text = (output or "").replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip() or "invalid" in text.lower()[:100]:
        return []

    hits: list[dict[str, str | None]] = []
    # Protocol  Address  Age  Hardware Addr  Type  Interface
    # Internet  10.1.1.5  0    0011.2233.4455  ARPA  Vlan10
    row_re = re.compile(
        r"(?:Internet|inet)\s+"
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<age>\S+)\s+"
        r"(?P<mac>[0-9a-fA-F.\-:]+)\s+"
        r"(?P<type>\S+)\s+"
        r"(?P<intf>\S+)",
        re.IGNORECASE,
    )
    # NX-OS: Address Age MAC Address Interface
    nx_re = re.compile(
        r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+"
        r"(?P<age>\S+)\s+"
        r"(?P<mac>[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\s+"
        r"(?P<intf>\S+)",
        re.IGNORECASE,
    )

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.lower().startswith(("protocol", "address", "flags")):
            continue
        match = row_re.search(stripped) or nx_re.search(stripped)
        if not match:
            continue
        mac = match.group("mac").lower()
        if mac in {"incomplete", "————", "----"}:
            continue
        hits.append(
            {
                "hostname": hostname,
                "switch_ip": switch_ip,
                "ip": match.group("ip"),
                "mac": mac,
                "vlan": None,
                "port": match.group("intf"),
                "source": "arp",
            }
        )
    return hits
