"""Server-side rendered web UI routes (Jinja2 templates, session-cookie auth)."""

import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import get_session_user
from gny.config import settings
from gny.database import get_db
from gny.models import Enrollment, Host, Log, User

router = APIRouter(tags=["ui"])

templates = Jinja2Templates(directory=str(Path(__file__).parent.parent / "templates"))

_log = logging.getLogger(__name__)


@router.get("/")
async def dashboard(
    request: Request,
    user: User = Depends(get_session_user),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard: list of pending enrollments (requires access_level >= 1)."""
    enrollments: list[Enrollment] = []
    if user.access_level >= 1:
        result = await db.execute(
            select(Enrollment)
            .where(
                Enrollment.confirmed_at.is_(None),
                Enrollment.deleted_at.is_(None),
            )
            .order_by(Enrollment.created_at.desc())
        )
        enrollments = list(result.scalars().all())
    return templates.TemplateResponse(
        request, "dashboard.html", {"user": user, "enrollments": enrollments}
    )


@router.post("/enroll/{enrollment_id}/confirm")
async def confirm_enrollment_ui(
    enrollment_id: int,
    request: Request,
    user: User = Depends(get_session_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm a pending enrollment via the web UI (requires access_level >= 1).

    Generates a new host Bearer token and displays it once on the result page.
    """
    if user.access_level < 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient access level to confirm enrollments",
        )

    result = await db.execute(select(Enrollment).where(Enrollment.id == enrollment_id))
    enrollment = result.scalar_one_or_none()

    if enrollment is None or not enrollment.is_pending:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Enrollment not found or not pending",
        )

    created_at = enrollment.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    timeout = timedelta(hours=settings.enroll_confirm_timeout_hours)
    if datetime.now(timezone.utc) - created_at > timeout:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment has expired",
        )

    # Upsert Host for this IP address
    host_result = await db.execute(
        select(Host).where(Host.ip_address == enrollment.ip_address)
    )
    host = host_result.scalar_one_or_none()
    now = datetime.now(timezone.utc)

    if host is None:
        host = Host(
            ip_address=enrollment.ip_address,
            ptr_record=enrollment.ptr_record,
            token=enrollment.token,
        )
        db.add(host)
        await db.flush()
    else:
        host.token = enrollment.token
        host.ptr_record = enrollment.ptr_record
        host.updated_at = now

    enrollment.host_id = host.id
    enrollment.confirmed_at = now
    request.state.enrollment_id = enrollment.id
    request.state.host_id = host.id
    await db.commit()

    _log.info(
        "Enrollment %s confirmed by user %s; host %s",
        enrollment.id,
        user.mail,
        host.ip_address,
    )

    return templates.TemplateResponse(
        request,
        "confirm_result.html",
        {
            "user": user,
            "enrollment": enrollment,
            "host": host,
        },
    )


@router.get("/logs")
async def logs_ui(
    request: Request,
    user: User = Depends(get_session_user),
    db: AsyncSession = Depends(get_db),
):
    """Recent logs table (requires access_level >= 4)."""
    if user.access_level < 4:
        return templates.TemplateResponse(
            request,
            "logs.html",
            {
                "user": user,
                "logs": None,
                "error": "access_level \u2265 4 required to view logs",
            },
        )
    result = await db.execute(select(Log).order_by(Log.id.desc()).limit(200))
    logs = list(result.scalars().all())
    return templates.TemplateResponse(
        request, "logs.html", {"user": user, "logs": logs, "error": None}
    )


@router.get("/users")
async def users_ui(
    request: Request,
    user: User = Depends(get_session_user),
    db: AsyncSession = Depends(get_db),
):
    """User list with grant-access controls (requires access_level >= 4)."""
    if user.access_level < 4:
        return templates.TemplateResponse(
            request,
            "users.html",
            {
                "user": user,
                "users": None,
                "error": "access_level \u2265 4 required to manage users",
            },
        )
    result = await db.execute(select(User).order_by(User.created_at))
    users = list(result.scalars().all())
    return templates.TemplateResponse(
        request, "users.html", {"user": user, "users": users, "error": None}
    )


@router.post("/users/{user_id}/grant")
async def grant_access(
    user_id: int,
    request: Request,
    user: User = Depends(get_session_user),
    db: AsyncSession = Depends(get_db),
):
    """Set access_level=1 for a level-0 user (requires access_level >= 4)."""
    if user.access_level < 4:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient access level",
        )
    result = await db.execute(
        select(User).where(User.id == user_id, User.access_level == 0)
    )
    target = result.scalar_one_or_none()
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found or already has access",
        )
    target.access_level = 1
    await db.commit()
    return RedirectResponse(url="/users", status_code=303)
