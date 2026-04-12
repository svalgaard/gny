import hashlib
import secrets
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gny.database import Base
from gny.models._utils import _utcnow

if TYPE_CHECKING:
    from gny.models.enrollment import Enrollment
    from gny.models.txt_record import TxtRecord


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    ptr_record: Mapped[str | None] = mapped_column(String(255), nullable=True)
    token: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )

    txt_records: Mapped[list["TxtRecord"]] = relationship(
        "TxtRecord", back_populates="host", cascade="all, delete-orphan"
    )
    enrollments: Mapped[list["Enrollment"]] = relationship(
        "Enrollment", back_populates="host"
    )

    @staticmethod
    def generate_token() -> str:
        return "gny-" + secrets.token_hex(24)

    @staticmethod
    def hash_token(token: str) -> str:
        """Return the SHA-256 hex digest of *token* for safe DB storage."""
        return hashlib.sha256(token.encode()).hexdigest()

    def allows_name(self, name: str) -> bool:
        """Return True if this host is allowed to manage a TXT record with
        the given DNS name.

        Rules:
          - Strip the leading '_acme-challenge.' label if present.
          - The resulting domain must equal ptr_record or be a subdomain of it.
        """
        if not self.ptr_record:
            return False

        n = name.lower().rstrip(".")
        ptr = self.ptr_record.lower().rstrip(".")

        if n.startswith("_acme-challenge."):
            domain = n[len("_acme-challenge.") :]
        else:
            domain = n

        return domain == ptr or domain.endswith("." + ptr)
