from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .tenant import Tenant
    from .rbac import Role
    from .session import Session
    from .audit import AuditLog
    from .invite import Invite
    from .oauth import OAuthAccount


class User(Base):
    __tablename__ = "xauth_users"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    # Nullable — les users OAuth n'ont pas forcément de mot de passe
    hashed_password: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    mfa_backup_codes: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)  # JSON list of hashed codes
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    __table_args__ = (Index("ix_xauth_user_email", "email"),)

    tenant_memberships: Mapped[List["TenantMember"]] = relationship(
        "TenantMember", back_populates="user", cascade="all, delete-orphan"
    )
    sessions: Mapped[List["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[List["AuditLog"]] = relationship(
        "AuditLog", back_populates="user"
    )
    sent_invites: Mapped[List["Invite"]] = relationship(
        "Invite", back_populates="invited_by_user"
    )
    oauth_accounts: Mapped[List["OAuthAccount"]] = relationship(
        "OAuthAccount", back_populates="user", cascade="all, delete-orphan"
    )


class TenantMember(Base):
    __tablename__ = "xauth_tenant_members"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_tenants.id"), nullable=False
    )
    role_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("xauth_roles.id"), nullable=True
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    is_owner: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped["User"] = relationship("User", back_populates="tenant_memberships")
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="members")
    role: Mapped[Optional["Role"]] = relationship("Role", back_populates="members")
