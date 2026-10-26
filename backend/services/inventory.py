"""Load and validate device inventory from YAML.

Inventory holds device addresses/platforms only — never user passwords.
SSH credentials come exclusively from the in-memory session store.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path

import yaml
from pydantic import ValidationError

from backend.config import get_settings
from backend.models.schemas import DeviceInventoryItem, PlatformType

logger = logging.getLogger(__name__)


class InventoryError(Exception):
    """Raised when inventory cannot be loaded or parsed."""


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
