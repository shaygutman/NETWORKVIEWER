"""Device inventory and switch collection endpoints.

All live SSH collection uses the caller's ActiveSession credentials (from
frontend login). No environment-variable SSH passwords are accepted.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.auth.dependencies import ActiveSession, get_active_session, get_current_user
from backend.models.schemas import (
    ConnectivityProbeResult,
    DeviceSummary,
    SwitchDetail,
    SwitchOverview,
    UserInfo,
)
from backend.services import cisco_collector
from backend.services.audit import write_audit
from backend.services.inventory import InventoryError, load_inventory

router = APIRouter(prefix="/devices", tags=["devices"])


@router.get("", response_model=list[DeviceSummary])
async def list_devices(
    current_user: UserInfo = Depends(get_current_user),
) -> list[DeviceSummary]:
    try:
        devices = load_inventory()
    except InventoryError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
    write_audit(current_user.username, "list_devices", f"Listed {len(devices)} devices")
    return [
        DeviceSummary(
            hostname=d.hostname,
            ip=d.ip,
            platform=d.platform,
            site=d.site,
            role=d.role,
        )
        for d in devices
    ]


@router.get("/overview", response_model=list[SwitchOverview])
async def devices_overview(
    session: ActiveSession = Depends(get_active_session),
) -> list[SwitchOverview]:
    write_audit(
        session.user.username,
        "collect_overview",
        "Triggered fleet overview collection using session credentials",
    )
    return cisco_collector.collect_all_overviews(session.device_credentials)


@router.get("/{hostname}", response_model=SwitchDetail)
async def device_detail(
    hostname: str,
    session: ActiveSession = Depends(get_active_session),
) -> SwitchDetail:
    write_audit(
        session.user.username,
        "collect_detail",
        f"Collected detail for {hostname} using session credentials",
        hostname=hostname,
    )
    try:
        return cisco_collector.collect_switch_detail(hostname, session.device_credentials)
    except cisco_collector.CollectorError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{hostname}/probe", response_model=ConnectivityProbeResult)
async def device_connectivity_probe(
    hostname: str,
    session: ActiveSession = Depends(get_active_session),
) -> ConnectivityProbeResult:
    """
    Live SSH probe for one switch using the caller's login-session credentials.

    Used by the UI / operators to validate handshake, auth, model, firmware,
    and interface parsing without any ``SSH_TEST_*`` environment variables.
    """
    write_audit(
        session.user.username,
        "connectivity_probe",
        f"Probed {hostname} with session credentials (source=session)",
        hostname=hostname,
    )
    try:
        return cisco_collector.probe_switch_connectivity(
            hostname, session.device_credentials
        )
    except cisco_collector.CollectorError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{hostname}/commands", response_model=list[str])
async def device_recommended_commands(
    hostname: str,
    port: str | None = Query(default=None),
    current_user: UserInfo = Depends(get_current_user),
) -> list[str]:
    context = "port" if port else "switch"
    write_audit(
        current_user.username,
        "cli_recommendations",
        f"Requested {context} commands for {hostname}" + (f" port {port}" if port else ""),
        hostname=hostname,
    )
    return cisco_collector.recommended_commands_for(context, port=port)
