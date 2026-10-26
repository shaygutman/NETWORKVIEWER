"""Async background poller — read-only ``show`` collection into local cache.

Decouples GUI HTTP latency from live SSH. Cycles use Netmiko in a thread pool
and never enter configuration mode. Credentials come from optional dedicated
poller settings, otherwise from any active UI login session.
"""

from __future__ import annotations

import asyncio
import logging
import time
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from backend.auth.session_store import DeviceCredentials, credential_store
from backend.config import Settings, get_settings
from backend.services import cisco_collector
from backend.services.collector_cache import collector_cache

logger = logging.getLogger(__name__)

_cycle_lock = threading.Lock()


@dataclass
class PollerStatus:
    """Last-known background poll cycle status (process-local)."""

    enabled: bool = False
    running: bool = False
    interval_seconds: int = 600
    last_started_at: datetime | None = None
    last_finished_at: datetime | None = None
    last_duration_seconds: float | None = None
    last_devices_ok: int = 0
    last_devices_failed: int = 0
    last_error: str | None = None
    last_credential_source: str | None = None
    cycles_completed: int = 0
    next_run_hint: str = "idle"

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "running": self.running,
            "interval_seconds": self.interval_seconds,
            "last_started_at": self.last_started_at.isoformat() if self.last_started_at else None,
            "last_finished_at": self.last_finished_at.isoformat() if self.last_finished_at else None,
            "last_duration_seconds": self.last_duration_seconds,
            "last_devices_ok": self.last_devices_ok,
            "last_devices_failed": self.last_devices_failed,
            "last_error": self.last_error,
            "last_credential_source": self.last_credential_source,
            "cycles_completed": self.cycles_completed,
            "next_run_hint": self.next_run_hint,
        }


poller_status = PollerStatus()
_poll_task: asyncio.Task[None] | None = None
_stop_event: asyncio.Event | None = None


def resolve_poller_credentials(
    settings: Settings | None = None,
) -> tuple[DeviceCredentials | None, str]:
    """Prefer dedicated poller service account; else any active UI session."""
    cfg = settings or get_settings()
    user = (cfg.poller_ssh_username or "").strip()
    password = cfg.poller_ssh_password or ""
    if user and password:
        return DeviceCredentials(username=user, password=password), "poller_service_account"
    session_creds = credential_store.get_any_active_credentials()
    if session_creds is not None:
        return session_creds, "active_ui_session"
    return None, "none"


def run_fleet_poll_cycle(
    settings: Settings | None = None,
    *,
    only_if_cache_empty: bool = False,
) -> dict[str, Any]:
    """
    Synchronously poll every inventory switch (read-only) and refresh cache.

    Intended to run in a worker thread via ``asyncio.to_thread``.
    Overlapping cycles are skipped so the API stays responsive.
    """
    cfg = settings or get_settings()
    if only_if_cache_empty and collector_cache.list_overviews(sticky=True):
        logger.info("Skipping post-login warm — sticky cache already has snapshots")
        return {"ok": True, "skipped": True, "reason": "cache_warm"}

    if not _cycle_lock.acquire(blocking=False):
        logger.info("Skipping poll cycle — another collect is already running")
        return {"ok": False, "skipped": True, "reason": "already_running"}

    try:
        creds, source = resolve_poller_credentials(cfg)
        poller_status.last_credential_source = source
        if creds is None:
            message = (
                "Skipping poll cycle — no credentials "
                "(set POLLER_SSH_USERNAME/PASSWORD or keep a UI session signed in)"
            )
            logger.warning(message)
            poller_status.last_error = message
            return {
                "ok": False,
                "skipped": True,
                "reason": message,
                "credential_source": source,
            }

        started = time.monotonic()
        started_at = datetime.now(timezone.utc)
        poller_status.running = True
        poller_status.last_started_at = started_at
        poller_status.last_error = None
        logger.info(
            "Background poll cycle starting (credential_source=%s, workers=%s, interval=%ss)",
            source,
            cfg.collector_max_workers,
            cfg.collector_poll_interval_seconds,
        )

        try:
            overviews = cisco_collector.collect_all_overviews(
                creds,
                cfg,
                force_refresh=True,
            )
        except Exception as exc:  # noqa: BLE001
            duration = time.monotonic() - started
            poller_status.running = False
            poller_status.last_finished_at = datetime.now(timezone.utc)
            poller_status.last_duration_seconds = round(duration, 3)
            poller_status.last_error = str(exc)
            logger.exception("Background poll cycle failed after %.2fs: %s", duration, exc)
            return {
                "ok": False,
                "skipped": False,
                "error": str(exc),
                "duration_seconds": round(duration, 3),
                "credential_source": source,
            }

        ok = sum(1 for item in overviews if item.reachable)
        failed = len(overviews) - ok
        duration = time.monotonic() - started
        poller_status.running = False
        poller_status.last_finished_at = datetime.now(timezone.utc)
        poller_status.last_duration_seconds = round(duration, 3)
        poller_status.last_devices_ok = ok
        poller_status.last_devices_failed = failed
        poller_status.cycles_completed += 1

        logger.info(
            "Background poll cycle complete in %.2fs — %s reachable, %s failed, "
            "%s device(s) total (cache updated)",
            duration,
            ok,
            failed,
            len(overviews),
        )
        return {
            "ok": True,
            "skipped": False,
            "devices_total": len(overviews),
            "devices_ok": ok,
            "devices_failed": failed,
            "duration_seconds": round(duration, 3),
            "credential_source": source,
        }
    finally:
        _cycle_lock.release()


async def _poll_loop(settings: Settings) -> None:
    assert _stop_event is not None
    interval = max(60, int(settings.collector_poll_interval_seconds))
    poller_status.enabled = True
    poller_status.interval_seconds = interval
    # Short initial delay so the API can accept logins before the first cycle.
    poller_status.next_run_hint = "initial_delay"
    logger.info(
        "Background poller armed — first cycle in 15s, then every %ss",
        interval,
    )
    try:
        await asyncio.wait_for(_stop_event.wait(), timeout=15)
        return
    except asyncio.TimeoutError:
        pass

    while not _stop_event.is_set():
        poller_status.next_run_hint = "running"
        try:
            await asyncio.to_thread(run_fleet_poll_cycle, settings)
        except Exception as exc:  # noqa: BLE001
            logger.exception("Unhandled poller loop error: %s", exc)
            poller_status.last_error = str(exc)
        poller_status.next_run_hint = f"sleeping_{interval}s"
        try:
            await asyncio.wait_for(_stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            continue

    poller_status.enabled = False
    poller_status.running = False
    poller_status.next_run_hint = "stopped"
    logger.info("Background poller stopped")


def start_background_poller(settings: Settings | None = None) -> None:
    """Schedule the asyncio poll loop (call from FastAPI lifespan)."""
    global _poll_task, _stop_event
    cfg = settings or get_settings()
    if not cfg.collector_poll_enabled:
        poller_status.enabled = False
        poller_status.next_run_hint = "disabled"
        logger.info("Background poller disabled via COLLECTOR_POLL_ENABLED=false")
        return
    if _poll_task is not None and not _poll_task.done():
        logger.warning("Background poller already running")
        return
    _stop_event = asyncio.Event()
    _poll_task = asyncio.create_task(_poll_loop(cfg), name="nms-background-poller")
    logger.info(
        "Background poller task created (interval=%ss, sticky_cache_ttl=%ss)",
        cfg.collector_poll_interval_seconds,
        cfg.collector_cache_ttl_seconds,
    )


async def stop_background_poller() -> None:
    """Signal the poll loop to exit and await cancellation."""
    global _poll_task, _stop_event
    if _stop_event is not None:
        _stop_event.set()
    task = _poll_task
    _poll_task = None
    if task is not None:
        try:
            await asyncio.wait_for(task, timeout=10)
        except (asyncio.TimeoutError, asyncio.CancelledError):
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    _stop_event = None
    poller_status.next_run_hint = "stopped"
