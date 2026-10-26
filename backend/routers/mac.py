"""Global MAC address lookup endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.auth.dependencies import ActiveSession, get_active_session
from backend.models.schemas import MacLookupRequest, MacLookupResponse
from backend.services.audit import write_audit
from backend.services.cisco_collector import lookup_mac_across_inventory

router = APIRouter(prefix="/mac", tags=["mac"])


@router.post("/lookup", response_model=MacLookupResponse)
async def mac_lookup(
    payload: MacLookupRequest,
    session: ActiveSession = Depends(get_active_session),
) -> MacLookupResponse:
    hits, queried, failed, errors = lookup_mac_across_inventory(
        payload.mac,
        session.device_credentials,
        hostname=payload.hostname,
    )
    write_audit(
        session.user.username,
        "mac_lookup",
        f"Lookup {payload.mac} → {len(hits)} hit(s), {failed} device error(s)",
        success=failed == 0 or len(hits) > 0,
        hostname=payload.hostname,
    )
    return MacLookupResponse(
        query=payload.mac,
        normalized_mac=payload.mac,
        hits=hits,
        devices_queried=queried,
        devices_failed=failed,
        errors=errors,
    )
