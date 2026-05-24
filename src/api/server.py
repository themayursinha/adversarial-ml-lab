"""FastAPI application factory for the adversarial ML lab."""

from __future__ import annotations

from fastapi import FastAPI

from src.api.middleware import setup_middleware
from src.api.routes import router
from src.api.schemas import ErrorResponse


def create_app(
    title: str = "Adversarial ML Security Lab API",
    cors_origins: list[str] | None = None,
) -> FastAPI:
    app = FastAPI(
        title=title,
        version="0.2.1",
        description="API for scanning and evaluating LLM inputs against adversarial attacks.",
        responses={
            400: {"model": ErrorResponse},
            500: {"model": ErrorResponse},
            502: {"model": ErrorResponse},
        },
    )

    setup_middleware(app, cors_origins=cors_origins)
    app.include_router(router)

    return app
