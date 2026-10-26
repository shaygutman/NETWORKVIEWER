"""JWT creation and validation helpers.

JWTs intentionally contain NO passwords — only a session id (sid) that maps to
encrypted credentials held exclusively in server RAM.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from jose import JWTError, jwt

from backend.config import Settings, get_settings


def create_access_token(
    subject: str,
    extra_claims: dict[str, Any] | None = None,
    settings: Settings | None = None,
) -> tuple[str, int, datetime]:
    """Create a signed JWT and return (token, expires_in_seconds, expires_at_utc)."""
    cfg = settings or get_settings()
    expire_delta = timedelta(minutes=cfg.jwt_expire_minutes)
    expire_at = datetime.now(timezone.utc) + expire_delta
    payload: dict[str, Any] = {
        "sub": subject,
        "exp": expire_at,
        "iat": datetime.now(timezone.utc),
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, cfg.jwt_secret_key, algorithm=cfg.jwt_algorithm)
    return token, int(expire_delta.total_seconds()), expire_at


def decode_access_token(
    token: str,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Decode and validate a JWT. Raises JWTError on failure."""
    cfg = settings or get_settings()
    return jwt.decode(token, cfg.jwt_secret_key, algorithms=[cfg.jwt_algorithm])


def safe_decode_access_token(
    token: str,
    settings: Settings | None = None,
) -> dict[str, Any] | None:
    try:
        return decode_access_token(token, settings=settings)
    except JWTError:
        return None
