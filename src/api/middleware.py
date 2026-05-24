"""FastAPI middleware for security and observability."""

from __future__ import annotations

import time
from collections.abc import Awaitable
from typing import Callable

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response


def setup_middleware(app: FastAPI, cors_origins: list[str] | None = None) -> None:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_origins or ["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["*"],
        max_age=3600,
    )

    app.add_middleware(
        BaseHTTPMiddleware,
        dispatch=_request_logging,
    )


async def _request_logging(
    request: Request,
    call_next: Callable[[Request], Awaitable[Response]],
) -> Response:
    start = time.monotonic()
    response = await call_next(request)
    elapsed = (time.monotonic() - start) * 1000.0
    response.headers["X-Process-Time-Ms"] = str(round(elapsed, 2))
    return response
