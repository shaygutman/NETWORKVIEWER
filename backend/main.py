"""FastAPI application entrypoint for Network Operations Assistant."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.config import ensure_runtime_dirs, get_settings
from backend.models.schemas import HealthResponse
from backend.routers import audit, auth, baseline, devices, mac
from backend.services.inventory import InventoryError, load_inventory

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("network_ops")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    settings = get_settings()
    ensure_runtime_dirs(settings)
    try:
        devices = load_inventory()
        logger.info("Loaded %s device(s) from inventory", len(devices))
    except InventoryError as exc:
        logger.warning("Inventory not ready at startup: %s", exc)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Read-only Cisco switch monitoring and troubleshooting assistant",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(auth.router, prefix="/api")
    app.include_router(devices.router, prefix="/api")
    app.include_router(mac.router, prefix="/api")
    app.include_router(baseline.router, prefix="/api")
    app.include_router(audit.router, prefix="/api")

    @app.get("/api/health", response_model=HealthResponse, tags=["health"])
    async def health() -> HealthResponse:
        cfg = get_settings()
        try:
            count = len(load_inventory())
        except InventoryError:
            count = 0
        return HealthResponse(
            status="ok",
            app=cfg.app_name,
            version=cfg.app_version,
            auth_mode=cfg.auth_mode,
            device_count=count,
        )

    return app


app = create_app()
