"""Switch registration aliases (``POST /api/switches``).

The canonical implementation lives on ``POST /api/devices``. This router
exposes the same read-only register flow under the ``/switches`` path.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, status

from backend.auth.dependencies import ActiveSession, get_active_session
from backend.models.schemas import AddSwitchRequest, AddSwitchResponse
from backend.routers.devices import add_switch

router = APIRouter(prefix="/switches", tags=["switches"])


@router.post("", response_model=AddSwitchResponse, status_code=status.HTTP_201_CREATED)
@router.post("/", response_model=AddSwitchResponse, status_code=status.HTTP_201_CREATED)
async def register_switch(
    payload: AddSwitchRequest,
    session: ActiveSession = Depends(get_active_session),
) -> AddSwitchResponse:
    """Alias for ``POST /api/devices`` — read-only probe then inventory append."""
    return await add_switch(payload, session)
