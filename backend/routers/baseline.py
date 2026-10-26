"""Baseline configuration drift endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.auth.dependencies import ActiveSession, get_active_session, get_current_user
from backend.models.schemas import BaselineDiffResponse, UserInfo
from backend.services.audit import write_audit
from backend.services.baseline import compare_baseline, list_baselines

router = APIRouter(prefix="/baseline", tags=["baseline"])


@router.get("/files", response_model=list[str])
async def baseline_files(
    current_user: UserInfo = Depends(get_current_user),
) -> list[str]:
    write_audit(current_user.username, "list_baselines", "Listed baseline files")
    return list_baselines()


@router.get("/{hostname}", response_model=BaselineDiffResponse)
async def baseline_diff(
    hostname: str,
    session: ActiveSession = Depends(get_active_session),
) -> BaselineDiffResponse:
    result = compare_baseline(hostname, session.device_credentials)
    write_audit(
        session.user.username,
        "baseline_diff",
        f"Drift={'yes' if result.has_drift else 'no'} for {hostname}"
        + (f" ({result.error})" if result.error else ""),
        success=result.error is None,
        hostname=hostname,
    )
    return result
