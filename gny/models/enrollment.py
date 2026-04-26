import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

from fastapi import HTTPException, status
from sqlalchemy import DateTime, ForeignKey, Integer, String, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gny.database import Base
from gny.models._utils import _utcnow

if TYPE_CHECKING:
    from gny.models.host import Host


class Enrollment(Base):
    __tablename__ = "enrollments"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    ptr_record: Mapped[str | None] = mapped_column(String(255), nullable=True)
    mail: Mapped[str] = mapped_column(String(255), nullable=False)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    host_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="SET NULL"),
        nullable=True,
    )
    confirmed_by_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )

    @property
    def is_pending(self) -> bool:
        """True when this enrollment has not yet been confirmed or soft-deleted."""
        return self.confirmed_at is None and self.deleted_at is None

    host: Mapped["Host"] = relationship("Host", back_populates="enrollments")

    @staticmethod
    def generate_token() -> str:
        return "gny-" + secrets.token_hex(24)

    @staticmethod
    def hash_token(token: str) -> str:
        """Return the SHA-256 hex digest of *token* for safe DB storage."""
        return hashlib.sha256(token.encode()).hexdigest()


async def confirm_enrollment_for_host(
    enrollment: "Enrollment",
    db: AsyncSession,
    timeout_hours: float,
    confirmed_by_id: int | None = None,
) -> "Host":
    """Validate and confirm an enrollment, upserting the corresponding Host.

    Raises :class:`HTTPException` if the enrollment has expired.
    Returns the (possibly newly created) :class:`Host` with its token and
    ``contact_mail`` set from the enrollment.  The caller is responsible for
    calling ``db.commit()`` afterwards.
    """
    from gny.models.host import Host  # avoid circular import

    if enrollment.confirmed_at is not None:
        # Already confirmed — idempotent; reload Host for the caller
        result = await db.execute(select(Host).where(Host.id == enrollment.host_id))
        return result.scalar_one()

    created_at = enrollment.created_at
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    timeout = timedelta(hours=timeout_hours)
    if datetime.now(timezone.utc) - created_at > timeout:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Enrollment token has expired",
        )

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
            contact_mail=enrollment.mail,
            token=enrollment.token,
        )
        db.add(host)
        await db.flush()
    else:
        host.token = enrollment.token
        host.ptr_record = enrollment.ptr_record
        host.contact_mail = enrollment.mail
        host.updated_at = now

    enrollment.host_id = host.id
    enrollment.confirmed_by_id = confirmed_by_id
    enrollment.confirmed_at = now
    return host
