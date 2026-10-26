"""Medtronic ENT Active Directory / LDAP authentication.

Domain FQDN: ent.core.medtronic.com
Primary DC:  hcwe6f520b1.ent.core.medtronic.com

Passwords are used only for the LDAP bind and (separately) held encrypted in
server RAM for Netmiko SSH. They are never written to disk, audit logs, or
application logs.
"""

from __future__ import annotations

import logging
from typing import Any

from ldap3 import ALL, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException

from backend.auth.session_store import bare_sam_account
from backend.config import Settings, get_settings
from backend.models.schemas import UserInfo

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Raised when credentials are invalid or directory lookup fails."""


def authenticate_user(username: str, password: str, settings: Settings | None = None) -> UserInfo:
    """Authenticate against ENT LDAP or mock backend based on settings.auth_mode.

    The password argument must never be logged or persisted by this module.
    """
    cfg = settings or get_settings()
    clean_user = username.strip()
    if not clean_user or not password:
        raise AuthenticationError("Username and password are required")

    if cfg.auth_mode.lower() == "mock":
        return _authenticate_mock(clean_user, password, cfg)
    return _authenticate_ldap(clean_user, password, cfg)


def _authenticate_mock(username: str, password: str, cfg: Settings) -> UserInfo:
    sam = bare_sam_account(username)
    if sam.lower() != cfg.mock_username.lower() or password != cfg.mock_password:
        raise AuthenticationError("Invalid username or password")
    return UserInfo(
        username=sam,
        display_name=f"{sam} (mock)",
        email=None,
        groups=["NetworkOps-Read"],
        auth_mode="mock",
    )


def _build_ldap_server(cfg: Settings) -> Server:
    """Create ldap3 Server for the primary ENT domain controller."""
    host = cfg.ldap_server.strip()
    # Allow either bare hostname or ldap(s):// URL in config
    for prefix in ("ldaps://", "ldap://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix) :]
            break
    host = host.split("/")[0].split(":")[0]

    use_ssl = bool(cfg.ldap_use_ssl)
    port = cfg.ldap_port
    if use_ssl and port == 389:
        port = 636
    if not use_ssl and port == 636:
        use_ssl = True

    tls = Tls(validate=0) if use_ssl else None  # enterprise DC; validate via OS trust when available
    return Server(
        host,
        port=port,
        use_ssl=use_ssl,
        tls=tls,
        get_info=ALL,
        connect_timeout=10,
    )


def _authenticate_ldap(username: str, password: str, cfg: Settings) -> UserInfo:
    """Bind to Medtronic ENT Active Directory (UPN or domain\\user)."""
    server = _build_ldap_server(cfg)
    bind_candidates = _bind_identity_candidates(username, cfg)
    sam = bare_sam_account(username)

    try:
        if cfg.ldap_bind_dn:
            with Connection(
                server,
                user=cfg.ldap_bind_dn,
                password=cfg.ldap_bind_password,
                auto_bind=True,
                receive_timeout=15,
            ) as svc_conn:
                user_dn, attributes = _find_user(svc_conn, sam, cfg)

            with Connection(
                server,
                user=user_dn,
                password=password,
                auto_bind=True,
                receive_timeout=15,
            ):
                pass

            _assert_group_membership(attributes, cfg)
            return _user_info_from_attributes(sam, attributes)

        # Direct user bind — try UPN and domain-style identities (never log password)
        last_error: Exception | None = None
        for candidate in bind_candidates:
            try:
                with Connection(
                    server,
                    user=candidate,
                    password=password,
                    auto_bind=True,
                    receive_timeout=15,
                ) as user_conn:
                    try:
                        _user_dn, attributes = _find_user(user_conn, sam, cfg)
                    except AuthenticationError:
                        attributes = {
                            "cn": sam,
                            "displayName": sam,
                            "mail": f"{sam}@{cfg.ldap_upn_suffix}",
                            "memberOf": [],
                            "sAMAccountName": sam,
                        }
                    _assert_group_membership(attributes, cfg)
                    logger.info("LDAP bind succeeded for user %s via %s-style identity", sam, _identity_style(candidate))
                    return _user_info_from_attributes(sam, attributes)
            except LDAPException as exc:
                last_error = exc
                continue

        logger.warning("LDAP bind failed for user %s against %s", sam, cfg.ldap_server)
        if last_error is not None:
            raise AuthenticationError("ENT directory authentication failed") from last_error
        raise AuthenticationError("ENT directory authentication failed")

    except AuthenticationError:
        raise
    except LDAPException as exc:
        logger.warning("LDAP authentication failed for %s: %s", sam, exc.__class__.__name__)
        raise AuthenticationError("ENT directory authentication failed") from exc
    except Exception as exc:  # noqa: BLE001 — never leak internals or secrets
        logger.exception("Unexpected LDAP error for %s", sam)
        raise AuthenticationError("Authentication service unavailable") from exc


def _identity_style(candidate: str) -> str:
    if "@" in candidate:
        return "UPN"
    if "\\" in candidate:
        return "DOMAIN"
    return "SAM"


def _bind_identity_candidates(username: str, cfg: Settings) -> list[str]:
    """Build Medtronic ENT bind identities.

    Preferred forms:
      - username@ent.core.medtronic.com  (UPN)
      - ent.core.medtronic.com\\username  (FQDN domain bind)
      - ENT\\username                     (NetBIOS, if configured)
    """
    raw = username.strip()
    sam = bare_sam_account(raw)
    fqdn = (cfg.ldap_fqdn or cfg.ldap_upn_suffix or "ent.core.medtronic.com").lower()
    upn_suffix = cfg.ldap_upn_suffix or fqdn
    netbios = (cfg.ldap_domain or "ENT").strip()

    candidates: list[str] = []

    # Prefer exact user input when already UPN / DOMAIN\\user
    if "@" in raw or "\\" in raw:
        candidates.append(raw)

    # UPN (primary enterprise form)
    candidates.append(f"{sam}@{upn_suffix}")
    # FQDN\\user as requested for this environment
    candidates.append(f"{fqdn}\\{sam}")
    # Short NetBIOS DOMAIN\\user (common Windows form)
    if netbios:
        candidates.append(f"{netbios}\\{sam}")
    # Bare SAM last
    candidates.append(sam)

    seen: set[str] = set()
    ordered: list[str] = []
    for item in candidates:
        key = item.lower()
        if key not in seen:
            seen.add(key)
            ordered.append(item)
    return ordered


def _find_user(conn: Connection, username: str, cfg: Settings) -> tuple[str, dict[str, Any]]:
    sam = bare_sam_account(username)
    search_filter = f"(sAMAccountName={_escape_ldap_filter(sam)})"
    conn.search(
        search_base=cfg.ldap_user_search_base or cfg.ldap_base_dn,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["cn", "displayName", "mail", "memberOf", "sAMAccountName", "userPrincipalName"],
    )
    if not conn.entries:
        raise AuthenticationError("User not found in ENT directory")
    entry = conn.entries[0]
    attributes = {
        "cn": str(entry.cn) if "cn" in entry else None,
        "displayName": str(entry.displayName) if "displayName" in entry else None,
        "mail": str(entry.mail) if "mail" in entry else None,
        "memberOf": [str(g) for g in entry.memberOf.values] if "memberOf" in entry else [],
        "sAMAccountName": str(entry.sAMAccountName) if "sAMAccountName" in entry else sam,
    }
    return str(entry.entry_dn), attributes


def _assert_group_membership(attributes: dict[str, Any], cfg: Settings) -> None:
    allowed = (cfg.ldap_allowed_group or "").strip()
    if not allowed:
        return
    groups = [g.lower() for g in attributes.get("memberOf", [])]
    allowed_l = allowed.lower()
    if allowed_l not in groups and not any(allowed_l in g for g in groups):
        raise AuthenticationError("User is not a member of the authorized ENT group")


def _user_info_from_attributes(username: str, attributes: dict[str, Any]) -> UserInfo:
    return UserInfo(
        username=attributes.get("sAMAccountName") or bare_sam_account(username),
        display_name=attributes.get("displayName") or attributes.get("cn"),
        email=attributes.get("mail"),
        groups=list(attributes.get("memberOf") or []),
        auth_mode="ldap",
    )


def _escape_ldap_filter(value: str) -> str:
    """Escape special characters in LDAP filter values (RFC 4515)."""
    replacements = {
        "\\": r"\5c",
        "*": r"\2a",
        "(": r"\28",
        ")": r"\29",
        "\x00": r"\00",
    }
    for src, dst in replacements.items():
        value = value.replace(src, dst)
    return value
