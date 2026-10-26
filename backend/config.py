"""Application configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


ROOT_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Central runtime settings for Network Operations Assistant."""

    model_config = SettingsConfigDict(
        env_file=str(ROOT_DIR / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "Network Operations Assistant"
    app_version: str = "0.1.0"
    debug: bool = False

    # Paths
    inventory_path: Path = Field(default=ROOT_DIR / "inventory.yaml")
    baselines_dir: Path = Field(default=ROOT_DIR / "baselines")
    audit_log_path: Path = Field(default=ROOT_DIR / "backend" / "audit" / "audit.log")

    # JWT
    jwt_secret_key: str = Field(default="change-me-in-production-use-long-secret")
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 480

    # Auth mode: "ldap" (ENT AD) or "mock" (lab only — still uses in-memory SSH creds)
    auth_mode: str = Field(default="ldap")

    # Medtronic ENT Active Directory / LDAP
    # Primary DC: hcwe6f520b1.ent.core.medtronic.com
    ldap_server: str = Field(default="hcwe6f520b1.ent.core.medtronic.com")
    ldap_port: int = 389  # use 636 with LDAP_USE_SSL=true for LDAPS
    ldap_use_ssl: bool = False
    ldap_fqdn: str = Field(default="ent.core.medtronic.com")
    ldap_base_dn: str = Field(default="DC=ent,DC=core,DC=medtronic,DC=com")
    ldap_user_search_base: str = Field(default="DC=ent,DC=core,DC=medtronic,DC=com")
    ldap_bind_dn: str = Field(default="")
    ldap_bind_password: str = Field(default="")
    # Empty = any authenticated ENT user; set a group DN to restrict access
    ldap_allowed_group: str = Field(default="")
    ldap_domain: str = Field(default="ENT")  # NetBIOS short name
    ldap_upn_suffix: str = Field(default="ent.core.medtronic.com")

    # Mock auth users (username:password) used only when auth_mode=mock
    # Passwords are never written to disk by the app; .env is operator-managed only.
    mock_username: str = Field(default="admin")
    mock_password: str = Field(default="admin")

    # SSH / collector (client-side only — never modifies switch config)
    # Keep conn/read timeouts short so offline devices fail fast.
    ssh_timeout: int = 5
    ssh_conn_timeout: int = 3
    collector_max_workers: int = 8
    # Soft freshness window for snapshots (seconds). GUI reads are sticky and
    # do not SSH; background polling refreshes entries within this window.
    collector_cache_ttl_seconds: int = 1800
    # Background poll interval (seconds). Default 10 minutes (range 5–15 min).
    collector_poll_interval_seconds: int = 600
    collector_poll_enabled: bool = True
    # Optional dedicated read-only poller service account (unattended cycles).
    # When empty, the poller reuses credentials from any active UI login session.
    poller_ssh_username: str = Field(default="")
    poller_ssh_password: str = Field(default="")
    # Durable SQLite cache (snapshots + unused-port / link-state history).
    cache_db_path: Path = Field(default=ROOT_DIR / "backend" / "data" / "nms_cache.db")
    # Ports continuously down this many days are flagged unused (capacity planning).
    # Aging uses SQLite history — independent of switch reboot uptime.
    stale_port_days: int = 30
    # PoE draw above this fraction of the port Max (Watts) is flagged high-draw.
    poe_high_draw_ratio: float = 0.8

    # CORS
    cors_origins: str = Field(
        default="http://localhost:5173,http://localhost:3000,http://localhost"
    )

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


def ensure_runtime_dirs(settings: Settings | None = None) -> None:
    """Create directories required at runtime."""
    cfg = settings or get_settings()
    cfg.baselines_dir.mkdir(parents=True, exist_ok=True)
    cfg.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
    cfg.cache_db_path.parent.mkdir(parents=True, exist_ok=True)
