"""Encrypted in-memory session credential store (RAM only, zero disk persistence).

Passwords are never written to disk, databases, cache files, or logs.
They exist only as Fernet ciphertext in process memory for the active session
and are wiped on logout, explicit destroy, or expiry cleanup.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.fernet import Fernet, InvalidToken

from backend.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class DeviceCredentials:
    """Ephemeral SSH credentials for the current request — never serialize to disk."""

    username: str
    password: str


@dataclass
class _SessionRecord:
    username: str
    ssh_username: str
    password_token: bytes
    expires_at: datetime


def _fernet() -> Fernet:
    """Derive a Fernet key from the JWT secret (process-local, not persisted as a file)."""
    digest = hashlib.sha256(get_settings().jwt_secret_key.encode("utf-8")).digest()
    return Fernet(urlsafe_b64encode(digest))


class CredentialSessionStore:
    """Thread-safe RAM-only map of session_id → encrypted password."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionRecord] = {}

    def store(
        self,
        session_id: str,
        *,
        username: str,
        ssh_username: str,
        password: str,
        expires_at: datetime,
    ) -> None:
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        token = _fernet().encrypt(password.encode("utf-8"))
        with self._lock:
            # Replace any prior session for this id without logging secrets
            self._sessions[session_id] = _SessionRecord(
                username=username,
                ssh_username=ssh_username,
                password_token=token,
                expires_at=expires_at,
            )
        # Avoid retaining the plaintext argument longer than needed in this frame
        del password

    def get_credentials(self, session_id: str) -> DeviceCredentials | None:
        self.purge_expired()
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None:
                return None
            if record.expires_at <= datetime.now(timezone.utc):
                self._destroy_locked(session_id)
                return None
            try:
                plaintext = _fernet().decrypt(record.password_token).decode("utf-8")
            except InvalidToken:
                logger.warning("Session credential token invalid; wiping session")
                self._destroy_locked(session_id)
                return None
            return DeviceCredentials(username=record.ssh_username, password=plaintext)

    def destroy(self, session_id: str) -> bool:
        with self._lock:
            return self._destroy_locked(session_id)

    def purge_expired(self) -> int:
        now = datetime.now(timezone.utc)
        removed = 0
        with self._lock:
            expired = [
                sid
                for sid, rec in self._sessions.items()
                if rec.expires_at <= now
            ]
            for sid in expired:
                if self._destroy_locked(sid):
                    removed += 1
        return removed

    def _destroy_locked(self, session_id: str) -> bool:
        record = self._sessions.pop(session_id, None)
        if record is None:
            return False
        # Overwrite ciphertext buffer then drop references
        mutable = bytearray(record.password_token)
        for i in range(len(mutable)):
            mutable[i] = 0
        record.password_token = b""
        return True


# Process-wide singleton — never serialized; dies with the worker process.
credential_store = CredentialSessionStore()


def bare_sam_account(username: str) -> str:
    """Strip DOMAIN\\ or user@realm wrappers for Cisco AAA username."""
    value = username.strip()
    if "\\" in value:
        value = value.split("\\")[-1]
    if "@" in value:
        value = value.split("@")[0]
    return value
