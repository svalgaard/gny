from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Integer, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from gny.database import Base
from gny.models._utils import _utcnow

if TYPE_CHECKING:
    from gny.models.host import Host


class TxtRecord(Base):
    __tablename__ = "txt_records"
    __table_args__ = (UniqueConstraint("name", "text", name="uq_name_text"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    host_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    text: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, default=_utcnow
    )

    host: Mapped["Host"] = relationship("Host", back_populates="txt_records")
