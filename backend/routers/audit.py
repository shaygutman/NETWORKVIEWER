"""Audit log query endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from backend.auth.dependencies import get_current_user
from backend.models.schemas import AuditEntry, UserInfo
from backend.services.audit import read_audit

router = APIRouter(prefix="/audit", tags=["audit"])


@router.get("", response_model=list[AuditEntry])
async def get_audit_log(
    limit: int = Query(default=100, ge=1, le=500),
    current_user: UserInfo = Depends(get_current_user),
) -> list[AuditEntry]:
    _ = current_user
    return read_audit(limit=limit)
