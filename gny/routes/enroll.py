import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import get_authenticated_user
from gny.config import settings
from gny.database import get_db
from gny.dns_utils import get_ptr_records
from gny.models import Enrollment, User
from gny.models.enrollment import confirm_enrollment_for_host

router = APIRouter(tags=["enrollment"])


class EnrollRequest(BaseModel):
    mail: EmailStr


class EnrollResponse(BaseModel):
    token: str
    ip_address: str
    ptr_record: str


class ConfirmRequest(BaseModel):
    token: str


class ConfirmResponse(BaseModel):
    status: str = "ok"
    host_id: int
    ip_address: str


class ErrorResponse(BaseModel):
    error: str


@router.post(
    "/enroll",
    response_model=EnrollResponse,
    responses={
        400: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
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

    # Restrict enrollment to configured networks (default: RFC 1918)
    try:
        client_addr = ipaddress.ip_address(client_host)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid client IP address"
        )
    allowed = any(
        client_addr in ipaddress.ip_network(cidr, strict=False)
        for cidr in settings.enroll_allowed_networks
    )
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Enrollment not allowed from this IP address",
        )

    # Resolve PTR record; reject if none or not unique
    ptrs = await get_ptr_records(client_host)
    if len(ptrs) != 1:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="IP address does not have a unique PTR record",
        )
    ptr = ptrs[0]

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

    return EnrollResponse(token=token, ip_address=client_host, ptr_record=ptr)


@router.post(
    "/enroll/confirm",
    response_model=ConfirmResponse,
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
    associated user has ``access_level >= 1``.

    Users with ``access_level == 1`` can only confirm enrollments whose
    contact email matches their own.  Users with ``access_level >= 2``
    can confirm any enrollment.
    """
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

    # Email match enforcement for level-1 users
    if user.access_level < 2:
        if user.mail.lower() != enrollment.mail.lower():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Email does not match the enrollment contact email",
            )

    host = await confirm_enrollment_for_host(
        enrollment,
        db,
        settings.enroll_confirm_timeout_hours,
        confirmed_by_id=user.id,
    )

    request.state.enrollment_id = enrollment.id
    request.state.host_id = host.id
    await db.commit()

    return ConfirmResponse(host_id=host.id, ip_address=host.ip_address)
