"""Access controls for a locally run API.

* Capture-control endpoints only accept requests from this machine, and require
  ``X-Capture-Token`` when ``NIDS_CAPTURE_TOKEN`` is configured.
* State-changing requests that carry a browser ``Origin`` header must come from an allowed
  dashboard origin (blocks cross-site form posts, which CORS alone does not prevent).
* Uploads whose declared size exceeds the limit are rejected before the body is parsed.
"""

from __future__ import annotations

import hmac

from fastapi import Depends, Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

from major_project.api.deps import get_state
from major_project.api.errors import ApiError
from major_project.api.state import AppState
from major_project.core.config import Settings

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
MULTIPART_OVERHEAD = 64 * 1024


def require_local_client(request: Request, state: AppState = Depends(get_state)) -> AppState:
    host = request.client.host if request.client else None
    if host not in state.settings.local_control_hosts:
        raise ApiError(403, "local_only", "This operation is only allowed from this machine.")
    return state


def require_capture_control(
    request: Request, state: AppState = Depends(require_local_client)
) -> AppState:
    expected = state.settings.capture_token
    if expected:
        supplied = request.headers.get("x-capture-token", "")
        if not hmac.compare_digest(supplied.encode(), expected.encode()):
            raise ApiError(401, "invalid_capture_token", "A valid X-Capture-Token is required.")
    return state


class OriginAndSizeGuard(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.allowed_origins = set(settings.cors_origins)
        self.upload_limits = {
            "/api/analyze/csv": settings.max_upload_bytes + MULTIPART_OVERHEAD,
            "/api/network/pcap": settings.max_pcap_bytes + MULTIPART_OVERHEAD,
        }

    async def dispatch(self, request: Request, call_next):
        if request.method in UNSAFE_METHODS:
            origin = request.headers.get("origin")
            if origin is not None and origin not in self.allowed_origins:
                return _error(
                    403, "origin_not_allowed", "Requests from this origin are not allowed."
                )
            limit = self.upload_limits.get(request.url.path)
            declared = request.headers.get("content-length")
            if limit is not None and declared is not None:
                try:
                    too_big = int(declared) > limit
                except ValueError:
                    return _error(400, "invalid_content_length", "Invalid Content-Length header.")
                if too_big:
                    return _error(413, "upload_too_large", "Upload exceeds the size limit.")
        return await call_next(request)


def _error(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse({"error": {"code": code, "message": message, "details": None}}, status)
