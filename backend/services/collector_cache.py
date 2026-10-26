"""Thread-safe in-memory cache for read-only switch collection results.

GUI reads use sticky (non-expiring) snapshots so API latency stays under ~100ms.
Background polling / manual refresh overwrite entries. Durable copies and
unused-port aging live in SQLite via ``cache_store``.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Generic, TypeVar

from backend.models.schemas import PortOperationalStatus, SwitchDetail, SwitchOverview
from backend.services import cache_store

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass
class _CacheEntry(Generic[T]):
    value: T
    expires_at: float
    updated_at: float


@dataclass
class TrackerIndexEntry:
    """Cached MAC/ARP/neighbor binding used by global search (client-side only)."""

    hostname: str
    switch_ip: str
    port: str | None = None
    vlan: str | None = None
    mac: str | None = None
    ip: str | None = None
    neighbor_hostname: str | None = None
    source: str = "cache"
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class CollectorCache:
    """Process-local cache keyed by switch hostname (lowercased)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._overviews: dict[str, _CacheEntry[SwitchOverview]] = {}
        self._details: dict[str, _CacheEntry[SwitchDetail]] = {}
        # hostname:port → first observed continuous-down timestamp (wall clock).
        self._port_down_since: dict[str, datetime] = {}
        # Fleet-wide bindings for global IP/MAC/hostname search.
        self._tracker_index: list[TrackerIndexEntry] = []
        self._tracker_expires_at: float = 0.0
        self._hydrated = False

    @staticmethod
    def _key(hostname: str) -> str:
        return hostname.strip().lower()

    @staticmethod
    def _port_key(hostname: str, port: str) -> str:
        return f"{hostname.strip().lower()}::{port.strip().lower()}"

    def hydrate_from_disk(self, ttl_seconds: int) -> None:
        """Load SQLite snapshots + port-down history after startup (once)."""
        with self._lock:
            if self._hydrated:
                return
            try:
                cache_store.ensure_cache_db()
                self._port_down_since = cache_store.load_port_down_since()
                overviews, details = cache_store.load_all_snapshots()
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to hydrate collector cache from SQLite: %s", exc)
                self._hydrated = True
                return

            ttl = max(1, int(ttl_seconds))
            now = time.monotonic()
            for overview in overviews:
                key = self._key(overview.hostname)
                self._overviews[key] = _CacheEntry(
                    value=overview, expires_at=now + ttl, updated_at=now
                )
            for detail in details:
                key = self._key(detail.hostname)
                self._details[key] = _CacheEntry(
                    value=detail, expires_at=now + ttl, updated_at=now
                )
                # Keep overview aligned with detail when both were restored.
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
                self._overviews[key] = _CacheEntry(
                    value=overview, expires_at=now + ttl, updated_at=now
                )
                self._ingest_tracker_from_detail(detail, ttl)
            self._hydrated = True
            logger.info(
                "In-memory cache hydrated: %s overview(s), %s detail(s), %s down-port(s)",
                len(self._overviews),
                len(self._details),
                len(self._port_down_since),
            )

    def get_overview(self, hostname: str, *, sticky: bool = True) -> SwitchOverview | None:
        return self._get(self._overviews, hostname, sticky=sticky)

    def set_overview(self, hostname: str, value: SwitchOverview, ttl_seconds: int) -> None:
        self._set(self._overviews, hostname, value, ttl_seconds)
        try:
            cache_store.save_overview_snapshot(value)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist overview snapshot for %s: %s", hostname, exc)

    def get_detail(self, hostname: str, *, sticky: bool = True) -> SwitchDetail | None:
        return self._get(self._details, hostname, sticky=sticky)

    def list_overviews(self, *, sticky: bool = True) -> list[SwitchOverview]:
        with self._lock:
            now = time.monotonic()
            values: list[SwitchOverview] = []
            expired: list[str] = []
            for key, entry in self._overviews.items():
                if not sticky and entry.expires_at <= now:
                    expired.append(key)
                    continue
                values.append(entry.value)
            if not sticky:
                for key in expired:
                    self._overviews.pop(key, None)
            return values

    def list_details(self, *, sticky: bool = True) -> list[SwitchDetail]:
        with self._lock:
            now = time.monotonic()
            alive: list[SwitchDetail] = []
            expired: list[str] = []
            for key, entry in self._details.items():
                if not sticky and entry.expires_at <= now:
                    expired.append(key)
                else:
                    alive.append(entry.value)
            if not sticky:
                for key in expired:
                    self._details.pop(key, None)
            return list(alive)

    def set_detail(self, hostname: str, value: SwitchDetail, ttl_seconds: int) -> None:
        self._set(self._details, hostname, value, ttl_seconds)
        # Keep fleet overview in sync with the freshest detail snapshot.
        overview = SwitchOverview(
            **value.model_dump(
                exclude={
                    "interfaces",
                    "recommended_commands",
                    "stale_port_days_threshold",
                    "ip_address",
                }
            )
        )
        self._set(self._overviews, hostname, overview, ttl_seconds)
        self._ingest_tracker_from_detail(value, ttl_seconds)
        self.persist_port_states_for_detail(value)
        try:
            cache_store.save_detail_snapshot(value)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist detail snapshot for %s: %s", hostname, exc)

    def note_port_link_state(self, hostname: str, port: str, is_down: bool) -> datetime | None:
        """
        Track continuous-down duration in memory during a collect.

        Durable SQLite persistence is flushed once per switch via
        ``persist_port_states_for_detail`` to avoid per-port DB thrashing.
        """
        key = self._port_key(hostname, port)
        with self._lock:
            if not is_down:
                self._port_down_since.pop(key, None)
                return None
            existing = self._port_down_since.get(key)
            if existing is None:
                existing = datetime.now(timezone.utc)
                self._port_down_since[key] = existing
            return existing

    def persist_port_states_for_detail(self, detail: SwitchDetail) -> None:
        """Batch-write this switch's port up/down history to SQLite (one transaction)."""
        states: dict[str, bool] = {}
        for iface in detail.interfaces:
            is_down = iface.status in {
                PortOperationalStatus.DOWN,
                PortOperationalStatus.ADMIN_DOWN,
                PortOperationalStatus.ERR_DISABLED,
            }
            states[iface.port] = is_down
        if not states:
            return
        try:
            applied = cache_store.apply_port_link_states(detail.hostname, states)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "SQLite batch port-history write failed for %s: %s",
                detail.hostname,
                exc,
            )
            return
        with self._lock:
            host = detail.hostname.strip().lower()
            for port, down_since in applied.items():
                key = f"{host}::{port}"
                if down_since is None:
                    self._port_down_since.pop(key, None)
                else:
                    self._port_down_since[key] = down_since

    def get_port_down_since(self, hostname: str, port: str) -> datetime | None:
        with self._lock:
            return self._port_down_since.get(self._port_key(hostname, port))

    def replace_tracker_index(self, entries: list[TrackerIndexEntry], ttl_seconds: int) -> None:
        with self._lock:
            self._tracker_index = list(entries)
            self._tracker_expires_at = time.monotonic() + max(1, int(ttl_seconds))

    def extend_tracker_index(self, entries: list[TrackerIndexEntry], ttl_seconds: int) -> None:
        with self._lock:
            if time.monotonic() > self._tracker_expires_at:
                self._tracker_index = []
            # Drop prior rows for the same switches being refreshed.
            hosts = {e.hostname.lower() for e in entries}
            self._tracker_index = [
                row for row in self._tracker_index if row.hostname.lower() not in hosts
            ]
            self._tracker_index.extend(entries)
            self._tracker_expires_at = time.monotonic() + max(1, int(ttl_seconds))

    def get_tracker_index(self) -> list[TrackerIndexEntry]:
        with self._lock:
            if time.monotonic() > self._tracker_expires_at:
                return []
            return list(self._tracker_index)

    def invalidate(self, hostname: str | None = None) -> None:
        with self._lock:
            if hostname is None:
                self._overviews.clear()
                self._details.clear()
                self._tracker_index.clear()
                self._tracker_expires_at = 0.0
                return
            key = self._key(hostname)
            self._overviews.pop(key, None)
            self._details.pop(key, None)
            self._tracker_index = [
                row for row in self._tracker_index if row.hostname.lower() != key
            ]

    def _ingest_tracker_from_detail(self, detail: SwitchDetail, ttl_seconds: int) -> None:
        entries: list[TrackerIndexEntry] = []
        for iface in detail.interfaces:
            if iface.neighbor_hostname or iface.neighbor_ip:
                entries.append(
                    TrackerIndexEntry(
                        hostname=detail.hostname,
                        switch_ip=detail.ip,
                        port=iface.port,
                        vlan=iface.vlan,
                        mac=None,
                        ip=iface.neighbor_ip,
                        neighbor_hostname=iface.neighbor_hostname,
                        source="neighbor",
                    )
                )
        if entries:
            self.extend_tracker_index(entries, ttl_seconds)

    def _get(
        self,
        store: dict[str, _CacheEntry[T]],
        hostname: str,
        *,
        sticky: bool,
    ) -> T | None:
        key = self._key(hostname)
        with self._lock:
            entry = store.get(key)
            if entry is None:
                return None
            if not sticky and entry.expires_at <= time.monotonic():
                store.pop(key, None)
                return None
            return entry.value

    def _set(
        self,
        store: dict[str, _CacheEntry[T]],
        hostname: str,
        value: T,
        ttl_seconds: int,
    ) -> None:
        key = self._key(hostname)
        ttl = max(1, int(ttl_seconds))
        now = time.monotonic()
        with self._lock:
            store[key] = _CacheEntry(value=value, expires_at=now + ttl, updated_at=now)


# Shared singleton used by the collector service.
collector_cache = CollectorCache()
