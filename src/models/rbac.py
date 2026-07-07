from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, List, Optional
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    String,
    Table,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .tenant import Tenant
    from .user import TenantMember


# Association table for Role <-> Permission
role_permission_table = Table(
    "xauth_role_permissions",
    Base.metadata,
    Column("role_id", String(36), ForeignKey("xauth_roles.id"), primary_key=True),
    Column(
        "permission_id",
        String(36),
        ForeignKey("xauth_permissions.id"),
        primary_key=True,
    ),
)


class Role(Base):
    __tablename__ = "xauth_roles"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    tenant_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("xauth_tenants.id"), nullable=True
    )
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    tenant: Mapped[Optional["Tenant"]] = relationship("Tenant", back_populates="roles")
    permissions: Mapped[List["Permission"]] = relationship(
        "Permission", secondary=role_permission_table, back_populates="roles"
    )
    members: Mapped[List["TenantMember"]] = relationship(
        "TenantMember", back_populates="role"
    )


class Permission(Base):
    __tablename__ = "xauth_permissions"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)

    # ── Agrégation depuis les manifestes plugins (event rbac.declare) ──────────
    # Plugin qui possède la permission. NULL = permission plateforme seedée.
    source_plugin: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Le owner d'un tenant peut-il déléguer cette permission à ses membres ?
    tenant_grantable: Mapped[bool] = mapped_column(Boolean, default=False)
    # Regroupement UI ("Stock", "Facturation"…).
    group: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    # Soft-disable quand le plugin source est retiré (jamais de hard-delete).
    active: Mapped[bool] = mapped_column(Boolean, default=True)

    roles: Mapped[List["Role"]] = relationship(
        "Role", secondary=role_permission_table, back_populates="permissions"
    )


class MemberRole(Base):
    """Rôle assigné à un membre dans un tenant — many-to-many (multi-rôles).

    Permet de composer plusieurs profils (= plusieurs rôles/plugins) sur un même
    user. Coexiste avec TenantMember.role_id (rôle « primaire » legacy posé par
    le seed/les invitations) : la résolution prend l'union des deux.
    """

    __tablename__ = "xauth_member_roles"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "tenant_id",
            "role_id",
            "scope_type",
            "scope_id",
            name="uq_member_role",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_tenants.id"), nullable=False
    )
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_roles.id"), nullable=False
    )
    # ── Scope générique (sous-tenant) ─────────────────────────────────────────
    # NULL/NULL = rôle GLOBAL au tenant (comportement historique). Sinon le rôle
    # n'est effectif que dans ce scope (ex: scope_type="entrepot", scope_id=<uuid>).
    # scope_id est OPAQUE pour Orchauth : c'est l'ID d'une entité d'un autre plugin
    # (pas de FK cross-plugin, comme user_id côté xcompany).
    scope_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scope_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    granted_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )

    role: Mapped["Role"] = relationship("Role")


class MemberPermission(Base):
    """Permission accordée DIRECTEMENT à un membre dans un tenant (toggles owner).

    Couche hybride : les permissions effectives d'un user = celles de son rôle
    ∪ celles-ci. Scopé par (user, tenant).
    """

    __tablename__ = "xauth_member_permissions"
    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "tenant_id",
            "permission_id",
            "scope_type",
            "scope_id",
            name="uq_member_permission",
        ),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id"), nullable=False
    )
    tenant_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_tenants.id"), nullable=False
    )
    permission_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_permissions.id"), nullable=False
    )
    # Scope générique — voir MemberRole.scope_type/scope_id. NULL = global au tenant.
    scope_type: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scope_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    granted_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    created_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=True
    )

    permission: Mapped["Permission"] = relationship("Permission")
