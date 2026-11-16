# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The FastAPI app — mounts the routers under /api/v1 and serves the command center.

Single-user, loopback. This is the reference control-plane deployment; nothing in the PrismPath
format requires it. Needs the `control-plane` optional extra (fastapi/uvicorn/pydantic).

`create_app` builds the app in one posture (full, or read only) around one session; `app` is the one
built from the settings at import. The session guard (`session.SessionGuard`) wraps everything.
"""
import html
import logging
import mimetypes
import os

from fastapi import APIRouter, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.routing import APIRoute
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from prismpath.ledgers.audit_log import AuditWriteError

from . import (attest, control, core, edit, events, inspect, observe,
               picker, policy, prove, quality)
from .posture import capability
from .session import META_NAME, Session, SessionGuard

API_PREFIX = "/api/v1"
STATIC_DIR = os.path.join(core.SETTINGS.package_dir, "static")
# The tags index.html ships with; the page route fills them with this launch's token and the console's
# posture as it serves the page, so the client shows read-only controls as unavailable instead of
# sending requests the guard refuses.
SESSION_META_EMPTY = f'<meta name="{META_NAME}" content="">'
POSTURE_META_NAME = "prismpath-posture"
POSTURE_META_EMPTY = f'<meta name="{POSTURE_META_NAME}" content="">'
# The client is ES modules, which a browser runs only when served with a JavaScript type, and the
# console sends nosniff. Python before 3.12 may not know .mjs, so the type is registered here.
mimetypes.add_type("text/javascript", ".mjs")

ROUTERS = (prove.router, observe.router, control.router, edit.router, events.router, inspect.router,
           quality.router, attest.router, policy.router, picker.router)


def _envelope(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": status_code, "message": message}})


async def _value_error(request: Request, exc: ValueError):
    # containment guards (safe_path, confine_project) raise ValueError, a client error, not a 500
    return _envelope(400, str(exc))


async def _http_error(request: Request, exc: StarletteHTTPException):
    return _envelope(exc.status_code, str(exc.detail))


async def _validation_error(request: Request, exc: RequestValidationError):
    return _envelope(422, "invalid request")


async def _audit_unwritable(request: Request, exc: AuditWriteError):
    # The intent is written before the effect, so an intent that could not be written means nothing
    # was done. A result that could not be written follows an effect that ran. The reason (a path, an
    # errno) goes to the server log, not into the body.
    logging.getLogger(__name__).error("audit write failed on %s", request.url.path, exc_info=exc)
    if isinstance(exc, core.audit.ResultUnrecorded):
        return _envelope(503, "the action ran, and the console's audit log could not record its result")
    return _envelope(503, "refused: the console's audit log could not record the action, so it was not done")


async def _unhandled(request: Request, exc: Exception):
    # The exception text carries internal paths and library detail; the operator reads it in the
    # server log (the traceback is already there), the HTTP body says only that it failed.
    return _envelope(500, "internal error")


def _page_text(session: Session, read_only: bool) -> str:
    """index.html with this launch's token in its session meta tag and the posture in its posture tag.
    The file on disk never holds either."""
    with open(os.path.join(STATIC_DIR, "index.html"), encoding="utf-8") as page_file:
        text = page_file.read()
    if SESSION_META_EMPTY not in text:
        raise RuntimeError("index.html has no session meta tag")
    if POSTURE_META_EMPTY not in text:
        raise RuntimeError("index.html has no posture meta tag")
    posture = "read-only" if read_only else "full"
    text = text.replace(SESSION_META_EMPTY, f'<meta name="{META_NAME}" content="{html.escape(session.token)}">', 1)
    return text.replace(POSTURE_META_EMPTY, f'<meta name="{POSTURE_META_NAME}" content="{posture}">', 1)


def _in_posture(router: APIRouter, read_only: bool) -> APIRouter:
    """The router itself in the full posture; in the read only posture, a router holding only its
    routes whose capability is not `write`. The routes keep their own tags and paths."""
    if not read_only:
        return router
    kept = APIRouter()
    kept.routes.extend(route for route in router.routes
                       if not (isinstance(route, APIRoute) and capability(route) == "write"))
    return kept


def create_app(read_only=None, session=None) -> FastAPI:
    """The console's ASGI app in one posture. `read_only=None` takes the posture from the settings.

    Every route under /api/v1 is mounted in the full posture; the read only posture leaves out each
    route whose capability is `write`, and the guard refuses a request for one with a 403 that says
    why. The session guard is the outermost layer, so a request with a foreign Host or Origin, or
    without the token, is refused before anything else runs."""
    read_only = core.SETTINGS.read_only if read_only is None else bool(read_only)
    session = session or Session.mint()
    application = FastAPI(
        title="PrismPath Mission Control",
        version="1",
        description="Proving + observability over flows — single-user, loopback. The reference "
                    "control-plane deployment; not required by the PrismPath format.",
        # The interactive docs load their script from a CDN, which the content security policy refuses
        # and which would run on the console's origin, where the page's token is one request away.
        # The schema stays at /openapi.json.
        docs_url=None, redoc_url=None,
    )
    # Read from the routers themselves, not from the app, whose route list nests included routers on
    # newer FastAPI releases.
    write_routes = frozenset((method, API_PREFIX + route.path) for router in ROUTERS for route in router.routes
                             if isinstance(route, APIRoute) and capability(route) == "write"
                             for method in route.methods)
    for router in ROUTERS:
        application.include_router(_in_posture(router, read_only), prefix=API_PREFIX)
    application.state.session = session
    application.state.read_only = read_only
    application.state.write_routes = write_routes

    application.add_exception_handler(AuditWriteError, _audit_unwritable)
    application.add_exception_handler(ValueError, _value_error)
    application.add_exception_handler(StarletteHTTPException, _http_error)
    application.add_exception_handler(RequestValidationError, _validation_error)
    application.add_exception_handler(Exception, _unhandled)

    @application.middleware("http")
    async def _limit_body_size(request: Request, call_next):
        """Reject oversized request bodies before they are buffered. The control plane is loopback and
        single-user, but an accidental multi-GB POST must not OOM it. This is a Content-Length gate; a
        chunked body without a length still hits the per-endpoint size check downstream (edit.write_file)."""
        cl = request.headers.get("content-length")
        if cl is not None and cl.isdigit() and int(cl) > core.SETTINGS.max_file_bytes:
            return _envelope(413, f"request body exceeds MC_MAX_FILE_BYTES ({core.SETTINGS.max_file_bytes} bytes)")
        return await call_next(request)

    # Added last, so it is the outermost layer: nothing runs for a request it refuses.
    application.add_middleware(SessionGuard, session=session, port=lambda: core.SETTINGS.port,
                               api_prefix=API_PREFIX, write_routes=write_routes, read_only=read_only)

    # The command center. The page itself is served by a route, which writes the token into it; the
    # rest of the static files are mounted last so the /api/v1 routes win over the catch-all.
    @application.get("/", include_in_schema=False)
    @application.get("/index.html", include_in_schema=False)
    def _index():
        return HTMLResponse(_page_text(session, read_only))

    if os.path.isdir(STATIC_DIR):
        application.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return application


app = create_app()
