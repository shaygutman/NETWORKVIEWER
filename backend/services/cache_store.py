"""SQLite-backed durable cache for switch snapshots and unused-port history.

Read-only toward switches — this module only persists locally what the
collector already gathered via ``show`` commands. Port-down aging survives
process restarts and is independent of switch reboot uptime.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path

from backend.config import get_settings
from backend.models.schemas import SwitchDetail, SwitchOverview

logger = logging.getLogger(__name__)

_lock = threading.RLock()
_initialized = False


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def db_path() -> Path:
    return Path(get_settings().cache_db_path)


def ensure_cache_db() -> Path:
    """Create the SQLite file and schema if missing (once per process)."""
    global _initialized
    path = db_path()
    if _initialized:
        return path
    path.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        if _initialized:
            return path
        with sqlite3.connect(path, timeout=30) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS port_link_state (
                    hostname TEXT NOT NULL,
                    port TEXT NOT NULL,
                    is_down INTEGER NOT NULL DEFAULT 1,
                    down_since TEXT,
                    last_seen_at TEXT NOT NULL,
                    PRIMARY KEY (hostname, port)
                );

                CREATE TABLE IF NOT EXISTS switch_snapshots (
                    hostname TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    collected_at TEXT,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (hostname, kind)
                );

                CREATE INDEX IF NOT EXISTS idx_port_link_down
                    ON port_link_state (is_down, hostname);
                """
            )
            conn.commit()
        _initialized = True
        logger.info("Cache database ready at %s", path)
    return path


def _connect() -> sqlite3.Connection:
    ensure_cache_db()
    conn = sqlite3.connect(db_path(), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def load_port_down_since() -> dict[str, datetime]:
    """Return ``hostname::port → down_since`` for ports currently down."""
    ensure_cache_db()
    out: dict[str, datetime] = {}
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT hostname, port, down_since FROM port_link_state WHERE is_down = 1"
            ).fetchall()
    for row in rows:
        down_since = _parse_iso(row["down_since"])
        if down_since is None:
            continue
        key = f"{str(row['hostname']).strip().lower()}::{str(row['port']).strip().lower()}"
        out[key] = down_since
    logger.info("Hydrated %s continuous-down port record(s) from SQLite", len(out))
    return out


def note_port_link_state(hostname: str, port: str, is_down: bool) -> datetime | None:
    """Persist one port transition (prefer ``apply_port_link_states`` during collects)."""
    result = apply_port_link_states(hostname, {port: is_down})
    return result.get(port.strip().lower()) or result.get(port.strip())


def apply_port_link_states(
    hostname: str,
    states: dict[str, bool],
) -> dict[str, datetime | None]:
    """
    Batch-update port up/down history for one switch in a single SQLite transaction.

    Returns map of port → down_since (or None when up).
    """
    ensure_cache_db()
    host = hostname.strip().lower()
    now = _utc_now()
    now_iso = _iso(now)
    out: dict[str, datetime | None] = {}
    if not states:
        return out

    with _lock:
        with _connect() as conn:
            for port, is_down in states.items():
                port_key = port.strip()
                port_norm = port_key.lower()
                if not is_down:
                    conn.execute(
                        """
                        INSERT INTO port_link_state
                            (hostname, port, is_down, down_since, last_seen_at)
                        VALUES (?, ?, 0, NULL, ?)
                        ON CONFLICT(hostname, port) DO UPDATE SET
                            is_down = 0,
                            down_since = NULL,
                            last_seen_at = excluded.last_seen_at
                        """,
                        (host, port_key, now_iso),
                    )
                    out[port_norm] = None
                    continue

                row = conn.execute(
                    "SELECT down_since, is_down FROM port_link_state WHERE hostname = ? AND port = ?",
                    (host, port_key),
                ).fetchone()
                existing = _parse_iso(row["down_since"]) if row and row["is_down"] else None
                if existing is None:
                    existing = now
                conn.execute(
                    """
                    INSERT INTO port_link_state (hostname, port, is_down, down_since, last_seen_at)
                    VALUES (?, ?, 1, ?, ?)
                    ON CONFLICT(hostname, port) DO UPDATE SET
                        is_down = 1,
                        down_since = excluded.down_since,
                        last_seen_at = excluded.last_seen_at
                    """,
                    (host, port_key, _iso(existing), now_iso),
                )
                out[port_norm] = existing
            conn.commit()
    return out


def save_overview_snapshot(overview: SwitchOverview) -> None:
    ensure_cache_db()
    host = overview.hostname.strip().lower()
    now = _utc_now()
    collected = overview.last_collected_at or now
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO switch_snapshots (hostname, kind, payload_json, collected_at, updated_at)
                VALUES (?, 'overview', ?, ?, ?)
                ON CONFLICT(hostname, kind) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    collected_at = excluded.collected_at,
                    updated_at = excluded.updated_at
                """,
                (host, overview.model_dump_json(), _iso(collected), _iso(now)),
            )
            conn.commit()


def save_detail_snapshot(detail: SwitchDetail) -> None:
    ensure_cache_db()
    host = detail.hostname.strip().lower()
    now = _utc_now()
    collected = detail.last_collected_at or now
    overview = SwitchOverview(
        **detail.model_dump(
            exclude={
                "interfaces",
                "recommended_commands",
                "stale_port_days_threshold",
                "ip_address",
            }
        )
    )
    with _lock:
        with _connect() as conn:
            conn.execute(
                """
                INSERT INTO switch_snapshots (hostname, kind, payload_json, collected_at, updated_at)
                VALUES (?, 'detail', ?, ?, ?)
                ON CONFLICT(hostname, kind) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    collected_at = excluded.collected_at,
                    updated_at = excluded.updated_at
                """,
                (host, detail.model_dump_json(), _iso(collected), _iso(now)),
            )
            conn.execute(
                """
                INSERT INTO switch_snapshots (hostname, kind, payload_json, collected_at, updated_at)
                VALUES (?, 'overview', ?, ?, ?)
                ON CONFLICT(hostname, kind) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    collected_at = excluded.collected_at,
                    updated_at = excluded.updated_at
                """,
                (host, overview.model_dump_json(), _iso(collected), _iso(now)),
            )
            conn.commit()


def load_all_snapshots() -> tuple[list[SwitchOverview], list[SwitchDetail]]:
    """Hydrate durable snapshots after process restart (GUI cold-start)."""
    ensure_cache_db()
    overviews: list[SwitchOverview] = []
    details: list[SwitchDetail] = []
    with _lock:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT hostname, kind, payload_json FROM switch_snapshots"
            ).fetchall()
    for row in rows:
        try:
            if row["kind"] == "detail":
                details.append(SwitchDetail.model_validate_json(row["payload_json"]))
            elif row["kind"] == "overview":
                overviews.append(SwitchOverview.model_validate_json(row["payload_json"]))
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "Skipping corrupt snapshot %s/%s: %s",
                row["hostname"],
                row["kind"],
                exc,
            )
    logger.info(
        "Hydrated %s overview and %s detail snapshot(s) from SQLite",
        len(overviews),
        len(details),
    )
    return overviews, details
