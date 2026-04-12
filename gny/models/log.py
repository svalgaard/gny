from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from gny.database import Base
from gny.models._utils import _utcnow


class Log(Base):
    """Audit log for every HTTP request handled by the API."""

    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    path: Mapped[str] = mapped_column(String(255), nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    host_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("hosts.id", ondelete="SET NULL"),
        nullable=True,
    )
    enrollment_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("enrollments.id", ondelete="SET NULL"),
        nullable=True,
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )
