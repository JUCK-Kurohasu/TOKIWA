"""FastAPI application factory.

Routers are auto-discovered: every module in ``tokiwa.api.routes`` that defines ``router: APIRouter`` is
included. Background services register themselves via ``tokiwa.runtime`` decorators.
"""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import IntegrityError

from tokiwa import __version__, runtime
from tokiwa.api.middleware import BodySizeLimitMiddleware
from tokiwa.api.pagination import offset_guard
from tokiwa.config import Settings, get_settings
from tokiwa.db.session import create_all, dispose_engine, init_engine
from tokiwa.plugins import import_submodules
from tokiwa.schemas.events import EVENT_FIELD_MAX_CHARS

log = logging.getLogger(__name__)

# Sensor/agent/Gate batches: these get server.max_ingest_body_bytes, everything else server.max_body_bytes.
INGEST_PATH_PREFIX = "/api/v1/ingest/"


def _warn_on_narrow_event_cap(settings: Settings) -> None:
    """Event strings are cut at EVENT_FIELD_MAX_CHARS; a wider detector window would never see the cut part."""
    inspect = settings.detection.web.max_inspect_chars
    if inspect > EVENT_FIELD_MAX_CHARS:
        log.warning(
            "detection.web.max_inspect_chars=%d exceeds the event field cap (%d chars): longer fields are "
            "truncated at ingest, so the extra inspection window is never used",
            inspect,
            EVENT_FIELD_MAX_CHARS,
        )


def _include_routers(app: FastAPI) -> None:
    for module in import_submodules("tokiwa.api.routes"):
        router = getattr(module, "router", None)
        if isinstance(router, APIRouter):
            # offset_guard: bounded ?offset on every list route, also those not using PageParams (#94).
            app.include_router(router, dependencies=[Depends(offset_guard)])


async def _integrity_error(request: Request, exc: Exception) -> JSONResponse:
    """Unique/foreign-key violations (e.g. two concurrent creates of the same username) are conflicts, not 500s.

    Raised either inside a route or by the commit in ``get_session`` (which runs before the response is sent).
    Only the first line of the driver message is logged: ``str(exc)`` carries the SQL statement and its bound
    parameters (password hashes, token hashes ...).
    """
    orig = getattr(exc, "orig", None)
    reason = (str(orig).splitlines() or [""])[0][:200] if orig is not None else type(exc).__name__
    log.warning("integrity error on %s %s: %s", request.method, request.url.path, reason)
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": "conflict: the request violates a uniqueness or integrity constraint"},
    )


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
        # Unknown API paths get a JSON 404, not the UI shell with 200: API clients and monitors read that as
        # success, and it hid typos in API paths (audit #93).
        api_path = full_path.lstrip("/")
        if api_path == "api" or api_path.startswith("api/"):
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Not Found")
        candidate = (static_dir / full_path).resolve()
        if full_path and candidate.is_file() and static_dir.resolve() in candidate.parents:
            return FileResponse(candidate)
        return FileResponse(index)


def create_app(*, run_jobs: bool = True, init_db: bool = True) -> FastAPI:
    settings = get_settings()
    _warn_on_narrow_event_cap(settings)

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
        # server.expose_docs (default true for compatibility; false recommended in production, audit #93): the
        # Swagger UI and the full OpenAPI document are unauthenticated and map the whole API surface for a
        # scanner. ReDoc is off (it was an undocumented second copy at /redoc that needs Google Fonts + blob
        # workers in the CSP); the OAuth2 redirect page lives under /api/docs/ with the docs' CSP.
        docs_url="/api/docs" if settings.server.expose_docs else None,
        openapi_url="/api/openapi.json" if settings.server.expose_docs else None,
        redoc_url=None,
        swagger_ui_oauth2_redirect_url="/api/docs/oauth2-redirect",
    )
    # Starlette: the middleware added last is the outermost. CORS stays outermost so that 413s etc. still carry
    # CORS headers for the browser.
    app.add_middleware(
        BodySizeLimitMiddleware,
        default_limit=settings.server.max_body_bytes,
        prefix_limits=[(INGEST_PATH_PREFIX, settings.server.max_ingest_body_bytes)],
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.server.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_exception_handler(IntegrityError, _integrity_error)
    _include_routers(app)
    static_dir = settings.server.static_dir
    if static_dir is None:
        default = Path(__file__).resolve().parents[4] / "frontend" / "dist"
        static_dir = default if default.is_dir() else None
    if static_dir is not None:
        _mount_frontend(app, Path(static_dir))
    return app
