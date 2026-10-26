"""Append-only JSONL audit log for admin actions and collection errors."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from backend.config import get_settings
from backend.models.schemas import AuditEntry

logger = logging.getLogger(__name__)


def write_audit(
    username: str,
    action: str,
    detail: str,
    *,
    success: bool = True,
    hostname: str | None = None,
) -> AuditEntry:
    entry = AuditEntry(
        timestamp=datetime.now(timezone.utc),
        username=username,
        action=action,
        detail=detail,
        success=success,
        hostname=hostname,
    )
    path = get_settings().audit_log_path
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(entry.model_dump_json() + "\n")
    except OSError as exc:
        logger.error("Failed to write audit log: %s", exc)
    return entry


def read_audit(limit: int = 100) -> list[AuditEntry]:
    path = get_settings().audit_log_path
    if not path.exists():
        return []
    entries: list[AuditEntry] = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(AuditEntry.model_validate(json.loads(line)))
            except Exception:  # noqa: BLE001
                continue
    except OSError as exc:
        logger.error("Failed to read audit log: %s", exc)
    entries.reverse()
    return entries
