"""Consistent JSON error responses. Internal details and stack traces are only logged."""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from major_project.services.csv_analysis import CsvRejectedError
from major_project.services.inference import InputValidationError

logger = logging.getLogger(__name__)


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, message: str, details=None):
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.details = details


def _body(code: str, message: str, details=None) -> dict:
    return {"error": {"code": code, "message": message, "details": details}}


def _clean_pydantic_errors(errors) -> list[dict]:
    cleaned = []
    for err in errors[:50]:
        loc = [str(p) for p in err.get("loc", ()) if p not in ("body",)]
        cleaned.append(
            {"location": ".".join(loc), "message": err.get("msg"), "type": err.get("type")}
        )
    return cleaned


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        return JSONResponse(_body(exc.code, exc.message, exc.details), status_code=exc.status_code)

    @app.exception_handler(InputValidationError)
    async def _invalid_features(_: Request, exc: InputValidationError):
        return JSONResponse(
            _body(
                "invalid_features",
                "Input does not satisfy the model's feature schema"
                + (" (first errors shown)" if exc.truncated else ""),
                [e.as_dict() for e in exc.errors],
            ),
            status_code=422,
        )

    @app.exception_handler(CsvRejectedError)
    async def _csv_rejected(_: Request, exc: CsvRejectedError):
        return JSONResponse(_body(exc.code, exc.message, exc.errors or None), exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _request_validation(_: Request, exc: RequestValidationError):
        return JSONResponse(
            _body(
                "request_validation",
                "Request failed validation",
                _clean_pydantic_errors(exc.errors()),
            ),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, "http_error")
        return JSONResponse(_body(code, str(exc.detail)), status_code=exc.status_code)

    @app.exception_handler(SQLAlchemyError)
    async def _database(_: Request, exc: SQLAlchemyError):
        logger.error("database error", exc_info=exc, extra={"error_code": type(exc).__name__})
        return JSONResponse(_body("database_error", "The database is unavailable."), 503)

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception):
        logger.error("unhandled error", exc_info=exc, extra={"error_code": type(exc).__name__})
        return JSONResponse(_body("internal_error", "An internal error occurred."), 500)
