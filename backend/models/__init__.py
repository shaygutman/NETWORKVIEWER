"""Pydantic domain models for Network Operations Assistant."""

from .schemas import (
    AuditEntry,
    AuthToken,
    BaselineDiffResponse,
    BaselineDiffLine,
    DeviceInventoryItem,
    DeviceSummary,
    InterfaceStatus,
    LoginRequest,
    MacLookupHit,
    MacLookupRequest,
    MacLookupResponse,
    PortDetail,
    SwitchDetail,
    SwitchOverview,
    UserInfo,
)

__all__ = [
    "AuditEntry",
    "AuthToken",
    "BaselineDiffResponse",
    "BaselineDiffLine",
    "DeviceInventoryItem",
    "DeviceSummary",
    "InterfaceStatus",
    "LoginRequest",
    "MacLookupHit",
    "MacLookupRequest",
    "MacLookupResponse",
    "PortDetail",
    "SwitchDetail",
    "SwitchOverview",
    "UserInfo",
]
