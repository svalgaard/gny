from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import get_authenticated_user, get_current_enrollment
from gny.database import get_db
from gny.models import Host, Log, User

router = APIRouter(tags=["logs"])

_DEFAULT_LIMIT = 100
_MAX_LIMIT = 1000


class LogEntry(BaseModel):
    id: int
    method: str
    path: str
    status_code: int
    ip_address: str | None
    host_id: int | None
    user_id: int | None
    created_at: datetime

    model_config = {"from_attributes": True}


class LogsResponse(BaseModel):
    logs: list[LogEntry]


class ErrorResponse(BaseModel):
    error: str


@router.get(
    "/logs",
    response_model=LogsResponse,
    responses={
        401: {"model": ErrorResponse},
    },
)
async def get_logs_for_host(
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    enrollment: Host = Depends(get_current_enrollment),
    db: AsyncSession = Depends(get_db),
):
    """Return recent log entries for the authenticated host
    (enrollment token required)."""
    result = await db.execute(
        select(Log)
        .where(Log.host_id == enrollment.id)
        .order_by(Log.id.desc())
        .limit(limit)
    )
    return LogsResponse(logs=[LogEntry.model_validate(r) for r in result.scalars()])


@router.get(
    "/logs/all",
    response_model=LogsResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
)
async def get_all_logs(
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=_MAX_LIMIT),
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Return all recent log entries.
    Requires a user token with ``access_level >= 4``."""
    if user.access_level < 4:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access_level >= 4 required to view all logs",
        )
    result = await db.execute(select(Log).order_by(Log.id.desc()).limit(limit))
    return LogsResponse(logs=[LogEntry.model_validate(r) for r in result.scalars()])
