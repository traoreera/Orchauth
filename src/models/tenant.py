from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, List, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .user import User, TenantMember
    from .rbac import Role
    from .invite import Invite
    from .audit import AuditLog


class Tenant(Base):
    __tablename__ = "xauth_tenants"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    settings: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # JSON
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(tz=timezone.utc))

    __table_args__ = (Index("ix_xauth_tenant_slug", "slug"),)

    members: Mapped[List["TenantMember"]] = relationship(
        "TenantMember", back_populates="tenant", cascade="all, delete-orphan"
    )
    roles: Mapped[List["Role"]] = relationship("Role", back_populates="tenant")
    invites: Mapped[List["Invite"]] = relationship("Invite", back_populates="tenant")
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog", back_populates="tenant"
    )
