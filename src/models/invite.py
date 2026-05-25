from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .tenant import Tenant
    from .user import User
    from .rbac import Role


class Invite(Base):
    __tablename__ = "xauth_invites"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_tenants.id"), nullable=False
    )
    role_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("xauth_roles.id"), nullable=True
    )
    invited_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    token: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, default=lambda: str(uuid4()))
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="invites")
    role: Mapped[Optional["Role"]] = relationship("Role")
    invited_by_user: Mapped["User"] = relationship(
        "User", back_populates="sent_invites"
    )
