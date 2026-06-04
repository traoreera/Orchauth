from __future__ import annotations

from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import selectinload

from ..models.rbac import MemberPermission, MemberRole, Permission, Role
from .base import BaseRepository


class RoleRepository(BaseRepository[Role]):
    model = Role

    async def get_with_permissions(self, role_id: str) -> Optional[Role]:
        result = await self.session.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.id == role_id)
        )
        return result.scalar_one_or_none()

    async def list_for_tenant(self, tenant_id: Optional[str]) -> list[Role]:
        # selectinload(permissions) : en async le lazy-load est impossible
        # (pas de greenlet) ; les réponses RoleResponse ont besoin des perms.
        stmt = select(Role).options(selectinload(Role.permissions))
        if tenant_id is None:
            stmt = stmt.where(Role.tenant_id.is_(None))
        else:
            stmt = stmt.where(
                (Role.tenant_id == tenant_id) | Role.tenant_id.is_(None)
            )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class PermissionRepository(BaseRepository[Permission]):
    model = Permission

    async def get_by_name(self, name: str) -> Optional[Permission]:
        result = await self.session.execute(
            select(Permission).where(Permission.name == name)
        )
        return result.scalar_one_or_none()

    async def list_by_plugin(self, plugin: str) -> list[Permission]:
        result = await self.session.execute(
            select(Permission).where(Permission.source_plugin == plugin)
        )
        return list(result.scalars().all())

    async def list_grantable(self) -> list[Permission]:
        """Permissions actives et délégables par un owner de tenant."""
        result = await self.session.execute(
            select(Permission).where(
                Permission.active.is_(True),
                Permission.tenant_grantable.is_(True),
            )
        )
        return list(result.scalars().all())


class MemberRoleRepository(BaseRepository[MemberRole]):
    model = MemberRole

    async def list_for_member(self, user_id: str, tenant_id: str) -> list[MemberRole]:
        result = await self.session.execute(
            select(MemberRole).where(
                MemberRole.user_id == user_id,
                MemberRole.tenant_id == tenant_id,
            )
        )
        return list(result.scalars().all())

    async def get_one(
        self, user_id: str, tenant_id: str, role_id: str
    ) -> Optional[MemberRole]:
        result = await self.session.execute(
            select(MemberRole).where(
                MemberRole.user_id == user_id,
                MemberRole.tenant_id == tenant_id,
                MemberRole.role_id == role_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_for_role(self, tenant_id: str, role_id: str) -> list[MemberRole]:
        result = await self.session.execute(
            select(MemberRole).where(
                MemberRole.tenant_id == tenant_id,
                MemberRole.role_id == role_id,
            )
        )
        return list(result.scalars().all())


class MemberPermissionRepository(BaseRepository[MemberPermission]):
    model = MemberPermission

    async def list_for_member(
        self, user_id: str, tenant_id: str
    ) -> list[MemberPermission]:
        result = await self.session.execute(
            select(MemberPermission)
            .options(selectinload(MemberPermission.permission))
            .where(
                MemberPermission.user_id == user_id,
                MemberPermission.tenant_id == tenant_id,
            )
        )
        return list(result.scalars().all())

    async def get_one(
        self, user_id: str, tenant_id: str, permission_id: str
    ) -> Optional[MemberPermission]:
        result = await self.session.execute(
            select(MemberPermission).where(
                MemberPermission.user_id == user_id,
                MemberPermission.tenant_id == tenant_id,
                MemberPermission.permission_id == permission_id,
            )
        )
        return result.scalar_one_or_none()
