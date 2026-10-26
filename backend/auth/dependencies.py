"""FastAPI dependency injectors for authenticated routes and SSH session credentials."""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import ExpiredSignatureError, JWTError, jwt

from backend.auth.session_store import DeviceCredentials, credential_store
from backend.config import get_settings
from backend.models.schemas import UserInfo

bearer_scheme = HTTPBearer(auto_error=True)


@dataclass
class ActiveSession:
    """Authenticated user plus ephemeral device credentials (RAM only)."""

    user: UserInfo
    session_id: str
    device_credentials: DeviceCredentials


def _wipe_session_from_token(token: str) -> None:
    """Best-effort wipe when a token is expired/invalid (never logs secrets)."""
    cfg = get_settings()
    try:
        payload = jwt.decode(
            token,
            cfg.jwt_secret_key,
            algorithms=[cfg.jwt_algorithm],
            options={"verify_exp": False},
        )
        session_id = payload.get("sid")
        if session_id:
            credential_store.destroy(str(session_id))
    except JWTError:
        return


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> UserInfo:
    """Validate Bearer JWT and ensure the in-memory credential session still exists."""
    session = await get_active_session(credentials)
    return session.user


async def get_active_session(
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> ActiveSession:
    """Return user context and decrypt SSH credentials from the RAM session store."""
    credential_store.purge_expired()
    token = credentials.credentials
    cfg = get_settings()

    try:
        payload = jwt.decode(token, cfg.jwt_secret_key, algorithms=[cfg.jwt_algorithm])
    except ExpiredSignatureError:
        _wipe_session_from_token(token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None
    except JWTError:
        _wipe_session_from_token(token)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from None

    if "sub" not in payload or "sid" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_id = str(payload["sid"])
    device_creds = credential_store.get_credentials(session_id)
    if device_creds is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session credentials unavailable. Please sign in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user = UserInfo(
        username=str(payload["sub"]),
        display_name=payload.get("display_name"),
        email=payload.get("email"),
        groups=list(payload.get("groups") or []),
        auth_mode=payload.get("auth_mode", "ldap"),
    )
    return ActiveSession(user=user, session_id=session_id, device_credentials=device_creds)


__all__ = [
    "ActiveSession",
    "get_active_session",
    "get_current_user",
]
