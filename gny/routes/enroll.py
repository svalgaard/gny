from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import get_authenticated_user
from gny.config import settings
from gny.database import get_db
from gny.dns_utils import get_unique_ptr_record
from gny.models import Enrollment, Host, User

router = APIRouter(tags=["enrollment"])


class EnrollRequest(BaseModel):
    mail: EmailStr


class EnrollResponse(BaseModel):
    token: str


class ConfirmRequest(BaseModel):
    token: str


class SuccessResponse(BaseModel):
    status: str = "ok"


class ErrorResponse(BaseModel):
    error: str


@router.post(
    "/enroll",
    response_model=EnrollResponse,
    responses={
        400: {"model": ErrorResponse},
        409: {"model": ErrorResponse},
    },
)
async def enroll(
    body: EnrollRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new server. Returns a Bearer token that becomes active
    after confirming enrollment via POST /enroll/confirm."""
    client_host = request.client.host if request.client else None
    if not client_host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot determine client IP"
        )

    # Resolve PTR record; reject if none or not unique
    ptr = await get_unique_ptr_record(client_host)
    if ptr is None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="IP address does not have a unique PTR record",
        )

    # Soft-delete any existing pending enrollments for this IP
    await db.execute(
        update(Enrollment)
        .where(
            Enrollment.ip_address == client_host,
            Enrollment.confirmed_at == None,  # noqa: E711
            Enrollment.deleted_at == None,  # noqa: E711
        )
        .values(deleted_at=datetime.now(timezone.utc))
    )

    # Create enrollment
    token = Enrollment.generate_token()
    enrollment = Enrollment(
        mail=str(body.mail),
        token=Enrollment.hash_token(token),
        ip_address=client_host,
        ptr_record=ptr,
    )
    db.add(enrollment)
    await db.flush()
    request.state.enrollment_id = enrollment.id
    await db.commit()

    return EnrollResponse(token=token)


@router.post(
    "/enroll/confirm",
    response_model=SuccessResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
)
async def confirm_enrollment(
    body: ConfirmRequest,
    request: Request,
    user: User = Depends(get_authenticated_user),
    db: AsyncSession = Depends(get_db),
):
    """Confirm a pending enrollment.  Requires an OAuth2 Bearer token whose
    associated user has ``access_level >= 1``."""
    if user.access_level < 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient access level to confirm enrollments",
        )

    result = await db.execute(
        select(Enrollment).where(Enrollment.token == Enrollment.hash_token(body.token))
    )
    enrollment = result.scalar_one_or_none()

    if enrollment is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid enrollment token",
        )

    if enrollment.confirmed_at is None:
        created_at = enrollment.created_at
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        timeout = timedelta(hours=settings.enroll_confirm_timeout_hours)
        if datetime.now(timezone.utc) - created_at > timeout:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Enrollment token has expired",
            )

    if enrollment.confirmed_at is not None:
        # Already confirmed — idempotent
        request.state.enrollment_id = enrollment.id
        request.state.host_id = enrollment.host_id
        return SuccessResponse()

    # Upsert Host for this IP
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
    await db.commit()

    request.state.enrollment_id = enrollment.id
    request.state.host_id = host.id
    return SuccessResponse()
