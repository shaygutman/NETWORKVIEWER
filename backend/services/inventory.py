"""Load and validate device inventory from YAML.

Inventory holds device addresses/platforms only — never user passwords.
SSH credentials come exclusively from the in-memory session store.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import socket
import threading
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import ValidationError

from backend.config import get_settings
from backend.models.schemas import DeviceInventoryItem, PlatformType

logger = logging.getLogger(__name__)

_inventory_lock = threading.Lock()

# DNS / inventory hostname labels (RFC 1123-ish, no underscores required by AD DNS).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_INVENTORY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class InventoryError(Exception):
    """Raised when inventory cannot be loaded or parsed."""


class InventoryConflictError(InventoryError):
    """Raised when the target switch is already present in inventory."""


def load_inventory(path: Path | None = None) -> list[DeviceInventoryItem]:
    """Parse inventory.yaml into typed device records."""
    inventory_path = path or get_settings().inventory_path
    if not inventory_path.exists():
        raise InventoryError(f"Inventory file not found: {inventory_path}")

    with inventory_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    devices_raw = raw.get("devices") if isinstance(raw, dict) else None
    if not isinstance(devices_raw, list):
        raise InventoryError("inventory.yaml must contain a top-level 'devices' list")

    devices: list[DeviceInventoryItem] = []
    for index, item in enumerate(devices_raw):
        if not isinstance(item, dict):
            logger.warning("Skipping invalid inventory entry at index %s", index)
            continue
        try:
            platform = item.get("platform", "cisco_ios")
            if platform == "cisco_xe":
                platform = PlatformType.CISCO_IOS.value
            device = DeviceInventoryItem(
                hostname=item["hostname"],
                ip=item["ip"],
                platform=PlatformType(platform),
                credential_group=item.get("credential_group", "session"),
                site=item.get("site"),
                role=item.get("role"),
                baseline_file=item.get("baseline_file"),
                enabled=bool(item.get("enabled", True)),
            )
            devices.append(device)
        except (KeyError, ValidationError, ValueError) as exc:
            logger.warning("Skipping invalid device entry %s: %s", item.get("hostname", index), exc)

    return [d for d in devices if d.enabled]


def get_device(hostname: str) -> DeviceInventoryItem | None:
    hostname_l = hostname.lower()
    for device in load_inventory():
        if device.hostname.lower() == hostname_l:
            return device
    return None


@lru_cache
def inventory_device_count() -> int:
    try:
        return len(load_inventory())
    except InventoryError:
        return 0


def clear_inventory_cache() -> None:
    inventory_device_count.cache_clear()


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip())
        return True
    except ValueError:
        return False


def is_valid_hostname(value: str) -> bool:
    return bool(_HOSTNAME_RE.match(value.strip()))


def resolve_switch_target(
    target: str,
    *,
    inventory_hostname: str | None = None,
) -> tuple[str, str]:
    """
    Resolve operator input to ``(inventory_hostname, ip)``.

    Accepts an IPv4/IPv6 address or DNS name. Never stores passwords.
    """
    cleaned = target.strip()
    if is_ip_address(cleaned):
        ip = str(ipaddress.ip_address(cleaned))
        host_id = (inventory_hostname or _default_hostname_for_ip(ip)).strip()
        if not _INVENTORY_ID_RE.match(host_id):
            raise InventoryError(
                "Inventory hostname must start with a letter or digit and use "
                "only letters, digits, dots, underscores, or hyphens"
            )
        return host_id, ip

    if not is_valid_hostname(cleaned):
        raise InventoryError(
            "Enter a valid IPv4/IPv6 address or DNS hostname "
            "(letters, digits, hyphens, and dots only)"
        )

    try:
        infos = socket.getaddrinfo(cleaned, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise InventoryError(f"Could not resolve DNS name '{cleaned}': {exc}") from exc

    ip: str | None = None
    for family, _type, _proto, _canon, sockaddr in infos:
        if family == socket.AF_INET:
            ip = sockaddr[0]
            break
        if ip is None and family == socket.AF_INET6:
            ip = sockaddr[0]
    if not ip:
        raise InventoryError(f"No usable A/AAAA record for '{cleaned}'")

    host_id = (inventory_hostname or cleaned.split(".")[0] or cleaned).strip()
    if not _INVENTORY_ID_RE.match(host_id):
        raise InventoryError(
            "Inventory hostname must start with a letter or digit and use "
            "only letters, digits, dots, underscores, or hyphens"
        )
    return host_id, ip


def add_device(
    device: DeviceInventoryItem,
    path: Path | None = None,
) -> DeviceInventoryItem:
    """
    Append a device to inventory.yaml (thread-safe).

    Raises InventoryConflictError if hostname or IP already exists.
    """
    inventory_path = path or get_settings().inventory_path
    with _inventory_lock:
        if not inventory_path.exists():
            raise InventoryError(f"Inventory file not found: {inventory_path}")

        with inventory_path.open("r", encoding="utf-8") as handle:
            raw = yaml.safe_load(handle) or {}

        if not isinstance(raw, dict):
            raise InventoryError("inventory.yaml root must be a mapping")

        devices_raw = raw.get("devices")
        if devices_raw is None:
            devices_raw = []
            raw["devices"] = devices_raw
        if not isinstance(devices_raw, list):
            raise InventoryError("inventory.yaml must contain a top-level 'devices' list")

        host_l = device.hostname.lower()
        ip_l = device.ip.lower()
        for item in devices_raw:
            if not isinstance(item, dict):
                continue
            existing_host = str(item.get("hostname", "")).lower()
            existing_ip = str(item.get("ip", "")).lower()
            if existing_host == host_l:
                raise InventoryConflictError(
                    f"Switch '{device.hostname}' is already in inventory"
                )
            if existing_ip == ip_l:
                raise InventoryConflictError(
                    f"IP {device.ip} is already monitored as '{item.get('hostname')}'"
                )

        entry: dict[str, object] = {
            "hostname": device.hostname,
            "ip": device.ip,
            "platform": device.platform.value,
            "enabled": bool(device.enabled),
        }
        if device.site:
            entry["site"] = device.site
        if device.role:
            entry["role"] = device.role
        if device.baseline_file:
            entry["baseline_file"] = device.baseline_file
        if device.credential_group and device.credential_group not in {"default", "session"}:
            entry["credential_group"] = device.credential_group

        devices_raw.append(entry)

        try:
            with inventory_path.open("w", encoding="utf-8") as handle:
                handle.write(
                    "# Network Operations Assistant — device inventory (read-only monitoring)\n"
                    "# SSH uses the logged-in ENT user credentials from encrypted server RAM only.\n"
                    "# Do not store user or shared switch passwords in this file.\n\n"
                )
                yaml.safe_dump(
                    raw,
                    handle,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                )
        except OSError as exc:
            raise InventoryError(
                f"Cannot write inventory file ({inventory_path}): {exc}. "
                "Ensure the Docker volume mounts inventory.yaml as writable."
            ) from exc

        clear_inventory_cache()
        logger.info(
            "Added switch %s (%s, %s) to inventory",
            device.hostname,
            device.ip,
            device.platform.value,
        )
        return device


def _default_hostname_for_ip(ip: str) -> str:
    """Match existing inventory naming: sw-10-168-2-79."""
    if ":" in ip:
        # Compact IPv6 for inventory id
        compact = ip.replace(":", "-").strip("-")
        return f"sw-{compact}"[:128]
    return f"sw-{ip.replace('.', '-')}"
