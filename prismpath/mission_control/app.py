"""The FastAPI app — mounts the routers under /api/v1 and serves the command center.

Single-user, loopback. This is the reference control-plane deployment; nothing in the PrismPath
format requires it. Needs the `control-plane` optional extra (fastapi/uvicorn/pydantic).
"""
import os

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import control, core, edit, events, observe, prove

API_PREFIX = "/api/v1"
STATIC_DIR = os.path.join(core.PKG_DIR, "static")

app = FastAPI(
    title="PrismPath Mission Control",
    version="1",
    description="Proving + observability over flows — single-user, loopback. The reference "
                "control-plane deployment; not required by the PrismPath format.",
)

app.include_router(prove.router, prefix=API_PREFIX)
app.include_router(observe.router, prefix=API_PREFIX)
app.include_router(control.router, prefix=API_PREFIX)
app.include_router(edit.router, prefix=API_PREFIX)
app.include_router(events.router, prefix=API_PREFIX)


def _envelope(status_code: int, message: str) -> JSONResponse:
    return JSONResponse(status_code=status_code, content={"error": {"code": status_code, "message": message}})


@app.exception_handler(ValueError)
async def _value_error(request: Request, exc: ValueError):
    # containment guards (_safe) raise ValueError — a client error, not a 500
    return _envelope(400, str(exc))


@app.exception_handler(StarletteHTTPException)
async def _http_error(request: Request, exc: StarletteHTTPException):
    return _envelope(exc.status_code, str(exc.detail))


@app.exception_handler(RequestValidationError)
async def _validation_error(request: Request, exc: RequestValidationError):
    return _envelope(422, "invalid request")


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    return _envelope(500, str(exc))


# The command center (Phase 4). Mounted last so the /api/v1 routes and /docs win over the catch-all.
if os.path.isdir(STATIC_DIR):
    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
