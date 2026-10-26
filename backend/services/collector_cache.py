"""Thread-safe in-memory TTL cache for read-only switch collection results.

Client-side only — never touches switch configuration. Entries expire after
``Settings.collector_cache_ttl_seconds`` (default 5 minutes).
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Generic, TypeVar

from backend.models.schemas import SwitchDetail, SwitchOverview

T = TypeVar("T")


@dataclass
class _CacheEntry(Generic[T]):
    value: T
    expires_at: float


class CollectorCache:
    """Process-local TTL cache keyed by switch hostname (lowercased)."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._overviews: dict[str, _CacheEntry[SwitchOverview]] = {}
        self._details: dict[str, _CacheEntry[SwitchDetail]] = {}

    @staticmethod
    def _key(hostname: str) -> str:
        return hostname.strip().lower()

    def get_overview(self, hostname: str) -> SwitchOverview | None:
        return self._get(self._overviews, hostname)

    def set_overview(self, hostname: str, value: SwitchOverview, ttl_seconds: int) -> None:
        self._set(self._overviews, hostname, value, ttl_seconds)

    def get_detail(self, hostname: str) -> SwitchDetail | None:
        return self._get(self._details, hostname)

    def set_detail(self, hostname: str, value: SwitchDetail, ttl_seconds: int) -> None:
        self._set(self._details, hostname, value, ttl_seconds)
        # Keep fleet overview in sync with the freshest detail snapshot.
        overview = SwitchOverview(**value.model_dump(exclude={"interfaces", "recommended_commands"}))
        self._set(self._overviews, hostname, overview, ttl_seconds)

    def invalidate(self, hostname: str | None = None) -> None:
        with self._lock:
            if hostname is None:
                self._overviews.clear()
                self._details.clear()
                return
            key = self._key(hostname)
            self._overviews.pop(key, None)
            self._details.pop(key, None)

    def _get(self, store: dict[str, _CacheEntry[T]], hostname: str) -> T | None:
        key = self._key(hostname)
        with self._lock:
            entry = store.get(key)
            if entry is None:
                return None
            if entry.expires_at <= time.monotonic():
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
        with self._lock:
            store[key] = _CacheEntry(value=value, expires_at=time.monotonic() + ttl)


# Shared singleton used by the collector service.
collector_cache = CollectorCache()
