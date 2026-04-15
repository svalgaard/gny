import secrets
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from gny.database import Base
from gny.models._utils import _utcnow


class Session(Base):
    """A browser session created after a successful OIDC login.

    Stored as an opaque 64-hex-character token in an HttpOnly cookie.
    Expired sessions are not automatically purged; the ``expires_at``
    column must be checked on every request.
    """

    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
        default=lambda: secrets.token_hex(32),
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
