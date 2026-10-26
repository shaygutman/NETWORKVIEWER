"""Global IP / MAC / hostname tracker endpoint (read-only fleet search)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from backend.auth.dependencies import ActiveSession, get_active_session
from backend.models.schemas import TrackerSearchRequest, TrackerSearchResponse
from backend.services.audit import write_audit
from backend.services.tracker import global_tracker_search

router = APIRouter(prefix="/tracker", tags=["tracker"])


@router.post("/search", response_model=TrackerSearchResponse)
async def tracker_search(
    payload: TrackerSearchRequest,
    session: ActiveSession = Depends(get_active_session),
) -> TrackerSearchResponse:
    result = await asyncio.to_thread(
        global_tracker_search,
        payload.query,
        session.device_credentials,
        payload.hostname,
    )
    write_audit(
        session.user.username,
        "tracker_search",
        f"Search {payload.query!r} → {len(result.hits)} hit(s), "
        f"{result.devices_failed} device error(s)",
        success=result.devices_failed == 0 or len(result.hits) > 0,
        hostname=payload.hostname,
    )
    return result
