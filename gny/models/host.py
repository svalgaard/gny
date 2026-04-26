import fnmatch
import hashlib
import secrets
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import JSON, DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gny.database import Base
from gny.dns_utils import get_a_records, get_ptr_records
from gny.models._utils import _utcnow

if TYPE_CHECKING:
    from gny.models.enrollment import Enrollment
    from gny.models.txt_record import TxtRecord


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, unique=True)
    ptr_record: Mapped[str | None] = mapped_column(String(255), nullable=True)
    allowed_names: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
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

    async def check_name(self, name: str) -> str | None:
        """Return None if this host may manage a TXT record with *name*, or
        a human-readable denial reason string otherwise.

        Rules (all must pass):
          1. *name* must start with '_acme-challenge.'.
          2. The host must have a ptr_record configured.
          3. The live PTR record for the host's IP must still match
             ptr_record and must be the only PTR record for that IP.
          4. The domain (name with '_acme-challenge.' stripped) must either:
               a. equal ptr_record, or
               b. have an A record whose value is the host's IP address, or
               c. match a glob pattern in allowed_names.
        """
        n = name.lower().rstrip(".")
        if not n.startswith("_acme-challenge."):
            return "Name must start with _acme-challenge."
        domain = n[len("_acme-challenge.") :]

        if not self.ptr_record:
            return "No PTR record configured for this host"

        ptr = self.ptr_record.lower().rstrip(".")

        live_ptrs = await get_ptr_records(self.ip_address)
        if len(live_ptrs) != 1 or live_ptrs[0] != ptr:
            return "PTR record for host IP has changed or is not unique"

        if domain == ptr:
            return None

        a_records = await get_a_records(domain)
        if self.ip_address in a_records:
            return None

        for pattern in self.allowed_names or []:
            if fnmatch.fnmatch(domain, pattern.lower()):
                return None

        return "Name is not authorized for this host"
