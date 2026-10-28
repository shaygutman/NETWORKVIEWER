"""Load and validate device inventory from YAML.

Inventory holds device addresses/platforms only — never user passwords.
SSH credentials come exclusively from the in-memory session store.
"""

from __future__ import annotations

import logging
import re
import threading
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import ValidationError

from backend.config import get_settings
from backend.models.schemas import DeviceInventoryItem, PlatformType

logger = logging.getLogger(__name__)

_inventory_write_lock = threading.Lock()


class InventoryError(Exception):
    """Raised when inventory cannot be loaded or parsed."""


class InventoryConflictError(InventoryError):
    """Raised when a hostname or IP is already present in inventory."""


def _parse_inventory_items(raw: object) -> list[dict]:
    if not isinstance(raw, dict):
        raise InventoryError("inventory.yaml must be a mapping with a 'devices' list")
    devices_raw = raw.get("devices")
    if not isinstance(devices_raw, list):
        raise InventoryError("inventory.yaml must contain a top-level 'devices' list")
    return [item for item in devices_raw if isinstance(item, dict)]


def _item_to_device(item: dict, index: int | str) -> DeviceInventoryItem | None:
    try:
        platform = item.get("platform", "cisco_ios")
        if platform == "cisco_xe":
            platform = PlatformType.CISCO_IOS.value
        return DeviceInventoryItem(
            hostname=item["hostname"],
            ip=item["ip"],
            platform=PlatformType(platform),
            credential_group=item.get("credential_group", "session"),
            site=item.get("site"),
            role=item.get("role"),
            baseline_file=item.get("baseline_file"),
            enabled=bool(item.get("enabled", True)),
        )
    except (KeyError, ValidationError, ValueError) as exc:
        logger.warning(
            "Skipping invalid device entry %s: %s",
            item.get("hostname", index),
            exc,
        )
        return None


def load_inventory(
    path: Path | None = None,
    *,
    include_disabled: bool = False,
) -> list[DeviceInventoryItem]:
    """Parse inventory.yaml into typed device records."""
    inventory_path = path or get_settings().inventory_path
    if not inventory_path.exists():
        raise InventoryError(f"Inventory file not found: {inventory_path}")

    with inventory_path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}

    devices: list[DeviceInventoryItem] = []
    for index, item in enumerate(_parse_inventory_items(raw)):
        device = _item_to_device(item, index)
        if device is None:
            continue
        if include_disabled or device.enabled:
            devices.append(device)
    return devices


def get_device(hostname: str) -> DeviceInventoryItem | None:
    hostname_l = hostname.lower()
    for device in load_inventory():
        if device.hostname.lower() == hostname_l:
            return device
    return None


def find_inventory_conflict(
    hostname: str,
    ip: str,
    path: Path | None = None,
) -> DeviceInventoryItem | None:
    """Return an existing inventory entry that collides on hostname or IP."""
    host_l = hostname.strip().lower()
    ip_l = ip.strip().lower()
    for device in load_inventory(path, include_disabled=True):
        if device.hostname.lower() == host_l or device.ip.strip().lower() == ip_l:
            return device
    return None


def _format_inventory_entry(device: DeviceInventoryItem) -> str:
    """Render one inventory device block (no passwords)."""
    lines = [
        f"  - hostname: {device.hostname}",
        f"    ip: {device.ip}",
        f"    platform: {device.platform.value}",
        "    enabled: true",
    ]
    if device.site:
        lines.append(f"    site: {device.site}")
    if device.role:
        lines.append(f"    role: {device.role}")
    if device.baseline_file:
        lines.append(f"    baseline_file: {device.baseline_file}")
    if device.credential_group and device.credential_group not in {"default", "session"}:
        lines.append(f"    credential_group: {device.credential_group}")
    return "\n".join(lines) + "\n"


def add_device_to_inventory(
    device: DeviceInventoryItem,
    path: Path | None = None,
) -> DeviceInventoryItem:
    """Append a switch to inventory.yaml and clear the inventory count cache.

    This mutates the local NMS inventory file only — never switch configuration.
    """
    inventory_path = path or get_settings().inventory_path
    with _inventory_write_lock:
        if not inventory_path.exists():
            raise InventoryError(f"Inventory file not found: {inventory_path}")

        conflict = find_inventory_conflict(device.hostname, device.ip, inventory_path)
        if conflict is not None:
            raise InventoryConflictError(
                f"Switch already in inventory as '{conflict.hostname}' ({conflict.ip})"
            )

        # Ensure parent exists and the file is writable before we append.
        try:
            text = inventory_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise InventoryError(f"Cannot read inventory file: {exc}") from exc

        if "devices:" not in text:
            raise InventoryError("inventory.yaml must contain a top-level 'devices:' key")

        block = _format_inventory_entry(device)
        if text and not text.endswith("\n"):
            text += "\n"
        if not text.endswith("\n\n") and not text.rstrip().endswith("devices:"):
            # Keep entries separated by a blank line when the file already has content.
            if text.rstrip() and not text.endswith("\n"):
                text += "\n"
        text = text.rstrip("\n") + "\n\n" + block

        try:
            inventory_path.write_text(text, encoding="utf-8")
        except OSError as exc:
            raise InventoryError(
                f"Cannot write inventory file ({inventory_path}): {exc}. "
                "If running in Docker, mount inventory.yaml read-write."
            ) from exc

        clear_inventory_cache()
        logger.info(
            "Added switch to inventory: hostname=%s ip=%s platform=%s",
            device.hostname,
            device.ip,
            device.platform.value,
        )
        return device


def default_inventory_hostname(address: str, resolved_ip: str) -> str:
    """Build a stable inventory id from an IP or DNS name."""
    if _is_ipv4(resolved_ip) and address.strip() == resolved_ip:
        return f"sw-{resolved_ip.replace('.', '-')}"
    if _is_ipv4(address.strip()):
        return f"sw-{address.strip().replace('.', '-')}"
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "-", address.strip().lower()).strip("-._")
    sanitized = sanitized[:64] or f"sw-{resolved_ip.replace('.', '-')}"
    if not re.match(r"^[A-Za-z0-9]", sanitized):
        sanitized = f"sw-{sanitized}"
    return sanitized[:64]


def _is_ipv4(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", value.strip()))


@lru_cache
def inventory_device_count() -> int:
    try:
        return len(load_inventory())
    except InventoryError:
        return 0


def clear_inventory_cache() -> None:
    inventory_device_count.cache_clear()
