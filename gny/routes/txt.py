from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from gny.auth import get_current_enrollment
from gny.database import get_db
from gny.models import Host, TxtRecord

router = APIRouter(tags=["txt"])


class SuccessResponse(BaseModel):
    status: str = "ok"


class ErrorResponse(BaseModel):
    error: str


def _require_allowed(name: str, enrollment: Host) -> None:
    """Raise 403 if this enrollment is not allowed to manage `name`."""
    if not enrollment.allows_name(name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to manage records for this domain",
        )


@router.post(
    "/txt",
    response_model=SuccessResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
)
async def add_txt_record(
    name: str = Query(..., description="Fully-qualified DNS record name"),
    text: str = Query(..., description="TXT record content"),
    enrollment: Host = Depends(get_current_enrollment),
    db: AsyncSession = Depends(get_db),
):
    """Create a DNS TXT record."""
    if not name or not text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="name and text are required"
        )

    _require_allowed(name, enrollment)

    # Upsert: ignore if identical record already exists
    result = await db.execute(
        select(TxtRecord).where(
            TxtRecord.name == name,
            TxtRecord.text == text,
        )
    )
    existing = result.scalar_one_or_none()
    if existing is None:
        record = TxtRecord(host_id=enrollment.id, name=name, text=text)
        db.add(record)
        await db.commit()

    return SuccessResponse()


@router.delete(
    "/txt",
    response_model=SuccessResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
)
async def delete_txt_record(
    name: str = Query(..., description="Fully-qualified DNS record name"),
    text: str = Query(..., description="TXT record content"),
    enrollment: Host = Depends(get_current_enrollment),
    db: AsyncSession = Depends(get_db),
):
    """Remove a DNS TXT record."""
    _require_allowed(name, enrollment)

    result = await db.execute(
        select(TxtRecord).where(
            TxtRecord.name == name,
            TxtRecord.text == text,
            TxtRecord.host_id == enrollment.id,
        )
    )
    record = result.scalar_one_or_none()
    if record is not None:
        await db.delete(record)
        await db.commit()

    return SuccessResponse()


@router.get(
    "/txt/test",
    response_model=SuccessResponse,
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
    },
)
async def test_txt_record(
    name: str = Query(..., description="Fully-qualified DNS record name to test"),
    enrollment: Host = Depends(get_current_enrollment),
):
    """Verify the authenticated host is allowed to manage a TXT record
    with the given name."""
    _require_allowed(name, enrollment)
    return SuccessResponse()
