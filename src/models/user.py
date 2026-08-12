from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional
from uuid import uuid4

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, relationship
from datetime import datetime, timezone
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
    mfa_backup_codes: Mapped[Optional[str]] = mapped_column(String(1024), nullable=True)
    created_at: Mapped[Optional[str]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )

    __table_args__ = (Index("ix_xauth_user_email", "email"),)

    @property
    def has_password(self) -> bool:
        """Lu par `UserResponse.model_validate(user)` (routes/auth.py `/me`).

        `UserResponse.has_password` a un défaut `False` sans cette propriété :
        Pydantic lit l'attribut du même nom sur l'objet ORM, or `hashed_password`
        (pas `has_password`) est la colonne réelle — sans elle, `/me` renvoyait
        `has_password: false` pour absolument tous les utilisateurs, y compris
        ceux avec un vrai mot de passe.
        """
        return self.hashed_password is not None

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
    notifications: Mapped[List["Notification"]] = relationship(  # type: ignore[name-defined]
        "Notification", back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def has_password(self) -> bool:
        """Lu par `UserResponse.model_validate(user, from_attributes=True)`
        (route GET /me) — sans cette propriété, `has_password` retombait
        systématiquement sur son défaut Pydantic (`False`) pour tous les
        utilisateurs, y compris ceux ayant un vrai mot de passe défini, car
        aucun attribut `has_password` n'existait sur ce modèle."""
        return self.hashed_password is not None


class TenantMember(Base):
    __tablename__ = "xauth_tenant_members"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    user_tenant_status: Mapped[bool] = mapped_column(Boolean, default=True)
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_tenants.id"), nullable=False
    )
    role_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("xauth_roles.id"), nullable=True
    )
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(tz=timezone.utc))
    is_owner: Mapped[bool] = mapped_column(Boolean, default=False)

    __table_args__ = (
        UniqueConstraint("user_id", "tenant_id", name="uq_tenant_member"),
    )

    user: Mapped["User"] = relationship("User", back_populates="tenant_memberships")
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="members")
    role: Mapped[Optional["Role"]] = relationship("Role", back_populates="members")
