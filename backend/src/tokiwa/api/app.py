"""FastAPI application factory.

Routers are auto-discovered: every module in ``tokiwa.api.routes`` that defines ``router: APIRouter`` is
included. Background services register themselves via ``tokiwa.runtime`` decorators.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from tokiwa import __version__, runtime
from tokiwa.config import get_settings
from tokiwa.db.session import create_all, dispose_engine, init_engine
from tokiwa.plugins import import_submodules

log = logging.getLogger(__name__)


def _include_routers(app: FastAPI) -> None:
    for module in import_submodules("tokiwa.api.routes"):
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            app.include_router(router)


def _mount_frontend(app: FastAPI, static_dir: Path) -> None:
    index = static_dir / "index.html"
    if not index.is_file():
        log.warning("static_dir %s has no index.html; frontend not served", static_dir)
        return
    assets = static_dir / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa(full_path: str) -> FileResponse:
        candidate = (static_dir / full_path).resolve()
        if full_path and candidate.is_file() and static_dir.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(index)


def create_app(*, run_jobs: bool = True, init_db: bool = True) -> FastAPI:
    settings = get_settings()

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if init_db:
            init_engine()
            await create_all()
        runtime.load_service_packages()
        await runtime.start(run_jobs=run_jobs)
        try:
            yield
        finally:
            await runtime.stop()
            if init_db:
                await dispose_engine()

    app = FastAPI(
        title="TOKIWA",
        version=__version__,
        description="LLM-driven SIEM/XDR against generative-AI-driven cyber attacks",
        lifespan=lifespan,
        docs_url="/api/docs",
        openapi_url="/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    _include_routers(app)
    static_dir = settings.server.static_dir
    if static_dir is None:
        default = Path(__file__).resolve().parents[4] / "frontend" / "dist"
        static_dir = default if default.is_dir() else None
    if static_dir is not None:
        _mount_frontend(app, Path(static_dir))
    return app
