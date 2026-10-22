"""FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from major_project.api.errors import ApiError
from major_project.api.state import AppState


def get_state(request: Request) -> AppState:
    return request.app.state.nids


def require_model(state: AppState = Depends(get_state)) -> AppState:
    if not state.model_ready:
        raise ApiError(
            503,
            "model_unavailable",
            "The intrusion-detection model is not loaded; predictions are unavailable. "
            "See GET /api/health for details.",
        )
    return state


def get_session(state: AppState = Depends(get_state)) -> Iterator[Session]:
    with state.db.session() as session:
        yield session
