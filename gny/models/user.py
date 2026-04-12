from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from gny.database import Base
from gny.models._utils import _utcnow


class User(Base):
    """Authenticated administrator / operator.

    Populated automatically on first OIDC login; ``access_level`` defaults to 0
    and must be raised manually before the user can confirm enrollments.

    ``uid`` holds the standard OIDC ``sub`` claim (Google) or ``oid`` claim
    (Azure AD/Entra ID) — whichever the provider exposes as ``sub`` in its
    userinfo response.
    """

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    uid: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    mail: Mapped[str] = mapped_column(String(255), nullable=False)
    access_level: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow, onupdate=_utcnow
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )
