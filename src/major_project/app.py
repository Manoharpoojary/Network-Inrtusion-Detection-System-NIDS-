"""FastAPI application factory."""

from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from major_project.api.errors import install_error_handlers
from major_project.api.routes import alerts, analyses, dashboard, network, predict, system
from major_project.api.security import OriginAndSizeGuard
from major_project.api.state import build_state
from major_project.core.config import Settings, get_settings
from major_project.core.logging import configure_logging

logger = logging.getLogger("major_project.http")

DESCRIPTION = """
Binary (Benign / Attack) intrusion detection on IoT **flow-feature records** using a trusted
Random Forest pipeline.

* Inputs must use the dataset's 35 feature definitions (see `GET /api/model/info`).
* `attack_probability` is the fraction of trees voting *attack*: an uncalibrated model estimate.
* Severity labels are configurable triage rules, not verified risk.
* Live-traffic inference is **disabled**: the model's features cannot be derived from real flows.
"""


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        state = build_state(settings)
        app.state.nids = state
        try:
            yield
        finally:
            if state.capture is not None:
                state.capture.shutdown()
            state.db.dispose()

    app = FastAPI(
        title="IoT Network Intrusion Detection API",
        version="0.1.0",
        description=DESCRIPTION,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
        allow_credentials=False,
    )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        start = time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            logger.info(
                "request",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "status": status,
                    "duration_ms": round((time.perf_counter() - start) * 1000, 1),
                },
            )

    app.add_middleware(OriginAndSizeGuard, settings=settings)
    install_error_handlers(app)
    for module in (system, predict, analyses, alerts, dashboard, network):
        app.include_router(module.router)
    return app
