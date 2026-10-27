"""Global MAC address lookup endpoint."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends

from backend.auth.dependencies import ActiveSession, get_active_session
from backend.models.schemas import MacLookupRequest, MacLookupResponse
from backend.services.audit import write_audit
from backend.services.cisco_collector import lookup_mac_across_inventory

router = APIRouter(prefix="/mac", tags=["mac"])


def _search_warning(
    failed: int,
    from_cache: int,
    hit_count: int,
) -> str | None:
    if failed <= 0:
        return None
    if hit_count > 0:
        return (
            f"Found {hit_count} hit(s). Partial coverage: {failed} switch(es) "
            f"unreachable/skipped"
            + (f"; cache used for {from_cache}" if from_cache > 0 else "")
        )
    if from_cache > 0:
        return (
            f"{failed} switch(es) unreachable/skipped — showing results from cache "
            f"for {from_cache} of them"
        )
    return (
        f"{failed} switch(es) unreachable/skipped — no cached MAC/ARP for those hosts. "
        "Run Live collect on reachable switches first so MAC tables are cached."
    )


@router.post("/lookup", response_model=MacLookupResponse)
async def mac_lookup(
    payload: MacLookupRequest,
    session: ActiveSession = Depends(get_active_session),
) -> MacLookupResponse:
    hits, queried, failed, errors, from_cache, unreachable = await asyncio.to_thread(
        lookup_mac_across_inventory,
        payload.mac,
        session.device_credentials,
        payload.hostname,
    )
    write_audit(
        session.user.username,
        "mac_lookup",
        f"Lookup {payload.mac} → {len(hits)} hit(s), {failed} unreachable/skipped, "
        f"{from_cache} cache host(s)",
        success=failed == 0 or len(hits) > 0,
        hostname=payload.hostname,
    )
    return MacLookupResponse(
        query=payload.mac,
        normalized_mac=payload.mac,
        hits=hits,
        devices_queried=queried,
        devices_failed=failed,
        devices_from_cache=from_cache,
        cache_fallback_used=from_cache > 0,
        unreachable_hosts=unreachable,
        warning=_search_warning(failed, from_cache, len(hits)),
        errors=errors,
    )
