"""Baseline configuration drift detection (running-config vs golden files)."""

from __future__ import annotations

import difflib
import logging
from datetime import datetime, timezone

from backend.auth.session_store import DeviceCredentials
from backend.config import Settings, get_settings
from backend.models.schemas import BaselineDiffLine, BaselineDiffResponse
from backend.services.cisco_collector import CollectorError, get_running_config
from backend.services.inventory import get_device

logger = logging.getLogger(__name__)


def compare_baseline(
    hostname: str,
    device_credentials: DeviceCredentials,
    settings: Settings | None = None,
) -> BaselineDiffResponse:
    """Fetch running-config and diff against the device's golden baseline file."""
    cfg = settings or get_settings()
    device = get_device(hostname)
    if device is None:
        return BaselineDiffResponse(
            hostname=hostname,
            baseline_file="",
            has_drift=False,
            added_lines=0,
            removed_lines=0,
            diff_lines=[],
            collected_at=datetime.now(timezone.utc),
            error=f"Device '{hostname}' not found in inventory",
        )

    baseline_name = device.baseline_file or f"{device.hostname}_baseline.cfg"
    baseline_path = cfg.baselines_dir / baseline_name
    if not baseline_path.exists():
        return BaselineDiffResponse(
            hostname=device.hostname,
            baseline_file=baseline_name,
            has_drift=False,
            added_lines=0,
            removed_lines=0,
            diff_lines=[],
            collected_at=datetime.now(timezone.utc),
            error=f"Baseline file not found: {baseline_name}",
        )

    try:
        running = get_running_config(device.hostname, device_credentials, cfg)
    except CollectorError as exc:
        return BaselineDiffResponse(
            hostname=device.hostname,
            baseline_file=baseline_name,
            has_drift=False,
            added_lines=0,
            removed_lines=0,
            diff_lines=[],
            collected_at=datetime.now(timezone.utc),
            error=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Failed to collect running-config for %s: %s", hostname, exc)
        return BaselineDiffResponse(
            hostname=device.hostname,
            baseline_file=baseline_name,
            has_drift=False,
            added_lines=0,
            removed_lines=0,
            diff_lines=[],
            collected_at=datetime.now(timezone.utc),
            error=f"Unable to collect running-config: {exc}",
        )

    baseline_text = baseline_path.read_text(encoding="utf-8", errors="replace")
    return build_diff(
        hostname=device.hostname,
        baseline_file=baseline_name,
        baseline_text=baseline_text,
        running_text=running,
    )


def build_diff(
    hostname: str,
    baseline_file: str,
    baseline_text: str,
    running_text: str,
) -> BaselineDiffResponse:
    """Pure diff builder — useful for unit tests without SSH."""
    baseline_lines = _normalize_config_lines(baseline_text)
    running_lines = _normalize_config_lines(running_text)

    matcher = difflib.SequenceMatcher(a=baseline_lines, b=running_lines, autojunk=False)
    diff_lines: list[BaselineDiffLine] = []
    added = 0
    removed = 0
    line_no = 0

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset, line in enumerate(baseline_lines[i1:i2]):
                line_no += 1
                diff_lines.append(
                    BaselineDiffLine(
                        tag="equal",
                        baseline_line=line,
                        running_line=running_lines[j1 + offset],
                        line_no=line_no,
                    )
                )
        elif tag == "delete":
            for line in baseline_lines[i1:i2]:
                line_no += 1
                removed += 1
                diff_lines.append(
                    BaselineDiffLine(
                        tag="delete",
                        baseline_line=line,
                        running_line=None,
                        line_no=line_no,
                    )
                )
        elif tag == "insert":
            for line in running_lines[j1:j2]:
                line_no += 1
                added += 1
                diff_lines.append(
                    BaselineDiffLine(
                        tag="insert",
                        baseline_line=None,
                        running_line=line,
                        line_no=line_no,
                    )
                )
        elif tag == "replace":
            # Emit deletes then inserts for clarity in the UI
            for line in baseline_lines[i1:i2]:
                line_no += 1
                removed += 1
                diff_lines.append(
                    BaselineDiffLine(
                        tag="delete",
                        baseline_line=line,
                        running_line=None,
                        line_no=line_no,
                    )
                )
            for line in running_lines[j1:j2]:
                line_no += 1
                added += 1
                diff_lines.append(
                    BaselineDiffLine(
                        tag="insert",
                        baseline_line=None,
                        running_line=line,
                        line_no=line_no,
                    )
                )

    return BaselineDiffResponse(
        hostname=hostname,
        baseline_file=baseline_file,
        has_drift=added > 0 or removed > 0,
        added_lines=added,
        removed_lines=removed,
        diff_lines=diff_lines,
        collected_at=datetime.now(timezone.utc),
        error=None,
    )


def list_baselines(settings: Settings | None = None) -> list[str]:
    cfg = settings or get_settings()
    if not cfg.baselines_dir.exists():
        return []
    return sorted(p.name for p in cfg.baselines_dir.glob("*.cfg"))


def _normalize_config_lines(text: str) -> list[str]:
    """Strip noise that commonly differs between captures without real drift."""
    skip_prefixes = (
        "Building configuration",
        "Current configuration",
        "!",
        "ntp clock-period",
        "Cryptochecksum",
    )
    lines: list[str] = []
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line:
            continue
        if any(line.startswith(prefix) for prefix in skip_prefixes):
            continue
        if line.startswith("!") and "Last configuration change" in line:
            continue
        lines.append(line)
    return lines
