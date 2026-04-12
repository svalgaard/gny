import hashlib
import secrets
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String
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
