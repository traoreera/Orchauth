from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .user import User


class Session(Base):
    __tablename__ = "xauth_sessions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    refresh_token: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    device_fingerprint: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True
    )
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )
    expires_at: Mapped[str] = mapped_column(DateTime(timezone=True), nullable=False)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    last_jti: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="sessions")

    @classmethod
    def build(
        cls,
        user_id: str,
        refresh_token: str,
        expires_at: datetime,
        *,
        tenant_id: str | None = None,
        ip_address: str | None = None,
        device_fingerprint: str | None = None,
        last_jti: str | None = None,
    ) -> Session:
        return cls(
            user_id=user_id,
            tenant_id=tenant_id,
            refresh_token=refresh_token,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            expires_at=expires_at,
            last_jti=last_jti,
        )
