from __future__ import annotations

from typing import TYPE_CHECKING, List, Optional
from uuid import uuid4

from sqlalchemy import ForeignKey, String, Table, Column
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

    roles: Mapped[List["Role"]] = relationship(
        "Role", secondary=role_permission_table, back_populates="permissions"
    )
