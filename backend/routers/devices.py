"""Device inventory and switch collection endpoints.

All live SSH collection uses the caller's ActiveSession credentials (from
frontend login). No environment-variable SSH passwords are accepted.

Live SSH work always runs in a worker thread (``asyncio.to_thread``) so the
API event loop stays responsive for cache-only GUI reads.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.auth.dependencies import ActiveSession, get_active_session, get_current_user
from backend.models.schemas import (
    AddSwitchRequest,
    AddSwitchResponse,
    ConnectivityProbeResult,
    DeviceSummary,
    ExecCommandRequest,
    ExecCommandResponse,
    SwitchDetail,
    SwitchOverview,
    UserInfo,
)
from backend.services import cisco_collector
from backend.services.audit import write_audit
from backend.services.inventory import (
    InventoryConflictError,
    InventoryError,
    load_inventory,
)

router = APIRouter(prefix="/devices", tags=["devices"])


@router.post("", response_model=AddSwitchResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=AddSwitchResponse, status_code=status.HTTP_201_CREATED)
@router.post(
    "/register",
    response_model=AddSwitchResponse,
    status_code=status.HTTP_201_CREATED,
    include_in_schema=False,
)
async def add_switch(
    payload: AddSwitchRequest,
    session: ActiveSession = Depends(get_active_session),
) -> AddSwitchResponse:
    """Register a new switch after a read-only SSH connectivity check.

    Uses the caller's login-session credentials. Runs ``show`` commands only —
    never configuration mode. On success the switch is appended to inventory.yaml
    and warmed into the sticky cache so the dashboard updates without a restart.
    """
    write_audit(
        session.user.username,
        "add_switch",
        f"Register switch address={payload.address!r} hostname={payload.hostname!r}",
    )
    try:
        result = await asyncio.to_thread(
            cisco_collector.register_new_switch,
            payload.address,
            session.device_credentials,
            hostname=payload.hostname,
            platform=payload.platform,
            site=payload.site,
            role=payload.role,
        )
    except InventoryConflictError as exc:
        write_audit(
            session.user.username,
            "add_switch_conflict",
            str(exc),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except InventoryError as exc:
        write_audit(
            session.user.username,
            "add_switch_failed",
            str(exc),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc
    except cisco_collector.CollectorError as exc:
        write_audit(
            session.user.username,
            "add_switch_failed",
            str(exc),
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=str(exc),
        ) from exc

    write_audit(
        session.user.username,
        "add_switch_ok",
        result.message,
        hostname=result.hostname,
        success=True,
    )
    return result


@router.get("", response_model=list[DeviceSummary])
async def list_devices(
    current_user: UserInfo = Depends(get_current_user),
) -> list[DeviceSummary]:
    try:
        devices = load_inventory()
    except InventoryError as exc:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)) from exc
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
    refresh: bool = Query(
        default=False,
        description=(
            "When false (default), serve sticky local cache only — no SSH. "
            "When true, run an on-demand live collect (manual live Refresh)."
        ),
    ),
) -> list[SwitchOverview]:
    if not refresh:
        # Hot path for the GUI — never SSH, never block the event loop on I/O waits.
        return await asyncio.to_thread(cisco_collector.list_cached_overviews)

    write_audit(
        session.user.username,
        "collect_overview",
        "On-demand live fleet overview collection using session credentials",
    )

    def _live_fleet() -> list[SwitchOverview]:
        from backend.services.background_poller import _cycle_lock

        if not _cycle_lock.acquire(blocking=False):
            # Another fleet collect is running — serve sticky cache immediately.
            return cisco_collector.list_cached_overviews()
        try:
            return cisco_collector.collect_all_overviews(
                session.device_credentials,
                force_refresh=True,
            )
        finally:
            _cycle_lock.release()

    return await asyncio.to_thread(_live_fleet)


@router.get("/{hostname}", response_model=SwitchDetail)
async def device_detail(
    hostname: str,
    session: ActiveSession = Depends(get_active_session),
    refresh: bool = Query(
        default=False,
        description=(
            "When false (default), serve sticky local cache only — no SSH. "
            "When true, run an on-demand live collect for this switch."
        ),
    ),
) -> SwitchDetail:
    if not refresh:
        try:
            cached = await asyncio.to_thread(cisco_collector.get_cached_detail, hostname)
        except cisco_collector.CollectorError as exc:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
        if cached is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=(
                    f"No cached data for '{hostname}' yet. "
                    "Wait for the background poller or use Live collect / Test SSH."
                ),
            )
        return cached

    write_audit(
        session.user.username,
        "collect_detail",
        f"On-demand live detail collection for {hostname} using session credentials",
        hostname=hostname,
    )
    try:
        return await asyncio.to_thread(
            lambda: cisco_collector.collect_switch_detail(
                hostname,
                session.device_credentials,
                force_refresh=True,
            )
        )
    except cisco_collector.CollectorError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/{hostname}/probe", response_model=ConnectivityProbeResult)
async def device_connectivity_probe(
    hostname: str,
    session: ActiveSession = Depends(get_active_session),
) -> ConnectivityProbeResult:
    """
    Live SSH probe for one switch using the caller's login-session credentials.

    Always bypasses the collector TTL cache (Test SSH). Used by the UI /
    operators to validate handshake, auth, model, firmware, and interface
    parsing without any ``SSH_TEST_*`` environment variables.
    """
    write_audit(
        session.user.username,
        "connectivity_probe",
        f"Probed {hostname} with session credentials (source=session, live)",
        hostname=hostname,
    )
    try:
        return await asyncio.to_thread(
            cisco_collector.probe_switch_connectivity,
            hostname,
            session.device_credentials,
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
    try:
        devices = load_inventory()
    except InventoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc)
        ) from exc
    platform = next(
        (d.platform for d in devices if d.hostname.lower() == hostname.lower()),
        None,
    )
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Device '{hostname}' not found in inventory",
        )
    return cisco_collector.recommended_commands_for(
        context, port=port, platform=platform
    )


@router.post("/{hostname}/exec-command", response_model=ExecCommandResponse)
async def device_exec_command(
    hostname: str,
    body: ExecCommandRequest,
    session: ActiveSession = Depends(get_active_session),
) -> ExecCommandResponse:
    """
    Execute one read-only ``show`` command on a switch via SSH.

    Permanently rejects configure / write / reload / mutating commands.
    Uses the caller's in-memory login-session credentials only.
    """
    try:
        safe_command = cisco_collector.validate_show_command(body.command)
    except cisco_collector.CommandRejectedError as exc:
        write_audit(
            session.user.username,
            "exec_command_blocked",
            f"Blocked command on {hostname}: {body.command!r} — {exc}",
            hostname=hostname,
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    write_audit(
        session.user.username,
        "exec_command",
        f"Executing read-only command on {hostname}: {safe_command}",
        hostname=hostname,
    )
    try:
        result = await asyncio.to_thread(
            cisco_collector.execute_show_command,
            hostname,
            safe_command,
            session.device_credentials,
        )
    except cisco_collector.CollectorError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

    if not result.success:
        write_audit(
            session.user.username,
            "exec_command_failed",
            f"Command failed on {hostname}: {safe_command} — {result.error or 'unknown'}",
            hostname=hostname,
            success=False,
        )
    return result
