"""Authentication endpoints — passwords never persisted to disk or audit detail fields."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from backend.auth.dependencies import ActiveSession, get_active_session, get_current_user
from backend.auth.jwt_handler import create_access_token
from backend.auth.ldap import AuthenticationError, authenticate_user
from backend.auth.session_store import bare_sam_account, credential_store
from backend.config import get_settings
from backend.models.schemas import AuthToken, LoginRequest, UserInfo
from backend.services.audit import write_audit
from backend.services.background_poller import run_fleet_poll_cycle

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])
optional_bearer = HTTPBearer(auto_error=False)


@router.post("/login", response_model=AuthToken)
async def login(payload: LoginRequest) -> AuthToken:
    settings = get_settings()
    username = payload.username.strip()
    password = payload.password
    try:
        user = authenticate_user(username, password, settings)
    except AuthenticationError as exc:
        write_audit(
            bare_sam_account(username),
            "login",
            "Authentication failed",
            success=False,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
        ) from exc

    session_id = str(uuid.uuid4())
    token, expires_in, expires_at = create_access_token(
        subject=user.username,
        extra_claims={
            "sid": session_id,
            "display_name": user.display_name,
            "email": user.email,
            "groups": user.groups,
            "auth_mode": user.auth_mode,
        },
        settings=settings,
    )

    credential_store.store(
        session_id,
        username=user.username,
        ssh_username=bare_sam_account(username) or user.username,
        password=password,
        expires_at=expires_at,
    )
    del password
    payload.password = ""

    write_audit(
        user.username,
        "login",
        "Successful login (credentials held in memory only)",
        success=True,
    )

    # Warm sticky cache in the background only when empty (login stays instant).
    if settings.collector_poll_enabled:
        async def _warm_cache_after_login() -> None:
            try:
                await asyncio.to_thread(
                    lambda: run_fleet_poll_cycle(settings, only_if_cache_empty=True)
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("Post-login cache warm failed: %s", exc)

        asyncio.create_task(_warm_cache_after_login(), name="nms-post-login-poll")

    return AuthToken(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=user,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    credentials: HTTPAuthorizationCredentials | None = Depends(optional_bearer),
) -> None:
    """Wipe in-memory credentials. Accepts expired tokens for best-effort cleanup."""
    if credentials is None:
        return None

    cfg = get_settings()
    session_id: str | None = None
    username = "unknown"
    try:
        payload = jwt.decode(
            credentials.credentials,
            cfg.jwt_secret_key,
            algorithms=[cfg.jwt_algorithm],
            options={"verify_exp": False},
        )
        session_id = str(payload["sid"]) if payload.get("sid") else None
        username = str(payload.get("sub") or "unknown")
    except JWTError:
        return None

    if session_id:
        credential_store.destroy(session_id)
        write_audit(username, "logout", "Session credentials wiped from memory", success=True)
    return None


@router.get("/me", response_model=UserInfo)
async def me(current_user: UserInfo = Depends(get_current_user)) -> UserInfo:
    return current_user


@router.get("/session-status")
async def session_status(session: ActiveSession = Depends(get_active_session)) -> dict[str, str | bool]:
    """Lightweight check that JWT + in-memory credentials are still present."""
    return {
        "authenticated": True,
        "username": session.user.username,
        "credentials_in_memory": True,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
