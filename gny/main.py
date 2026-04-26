import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

import gny
from gny.config import settings
from gny.database import SessionLocal, init_db
from gny.models import Log
from gny.routes import enroll, logs, txt, ui
from gny.routes.oidc import router as oidc_router

logging.basicConfig(level=settings.log_level.upper())


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="GNY DNS API",
    description=("API for managing DNS TXT records used by ACME dns-01 challenges."),
    version=gny.__version__,
    lifespan=lifespan,
)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    try:
        host_id = getattr(request.state, "host_id", None)
        enrollment_id = getattr(request.state, "enrollment_id", None)
        user_id = getattr(request.state, "user_id", None)
        ip_address = request.client.host if request.client else None
        async with SessionLocal() as db:
            db.add(
                Log(
                    method=request.method,
                    path=request.url.path,
                    status_code=response.status_code,
                    ip_address=ip_address,
                    host_id=host_id,
                    enrollment_id=enrollment_id,
                    user_id=user_id,
                )
            )
            await db.commit()
    except Exception:
        logging.getLogger(__name__).exception("Failed to write API log entry")
    return response


# Routes under /api (as per OpenAPI spec servers.url)
app.include_router(enroll.router, prefix="/api")
app.include_router(txt.router, prefix="/api")
app.include_router(logs.router, prefix="/api")

# Web UI (no prefix — serves /, /logs, /users, /enroll/{id}/confirm)
app.include_router(ui.router)

# OAuth2 callback at /.well-known/sso, /login, /logout
app.include_router(oidc_router)

# Static files (logo, etc.)
app.mount(
    "/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static"
)


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    if settings.display_errors.lower() in ("true", "1", "yes"):
        detail = str(exc)
    else:
        detail = "Internal server error"
    return JSONResponse(
        status_code=500,
        content={"error": detail},
    )
