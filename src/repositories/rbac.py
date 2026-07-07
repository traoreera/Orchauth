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

    async def get_by_name(self, name: str) -> Optional[Role]:
        result = await self.session.execute(
            select(Role)
            .options(selectinload(Role.permissions))
            .where(Role.name == name, Role.tenant_id.is_(None))
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
        """TOUS les rôles du membre, tous scopes confondus (usage UI/listing)."""
        result = await self.session.execute(
            select(MemberRole).where(
                MemberRole.user_id == user_id,
                MemberRole.tenant_id == tenant_id,
            )
        )
        return list(result.scalars().all())

    async def list_in_scope(
        self,
        user_id: str,
        tenant_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> list[MemberRole]:
        """Rôles d'un membre dans UN scope précis.

        scope_type=None → bucket GLOBAL (scope_type IS NULL AND scope_id IS NULL).
        Sinon → assignations exactement scopées (scope_type, scope_id).
        """
        stmt = select(MemberRole).where(
            MemberRole.user_id == user_id,
            MemberRole.tenant_id == tenant_id,
        )
        if scope_type is None:
            stmt = stmt.where(
                MemberRole.scope_type.is_(None), MemberRole.scope_id.is_(None)
            )
        else:
            stmt = stmt.where(
                MemberRole.scope_type == scope_type,
                MemberRole.scope_id == scope_id,
            )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_one(
        self,
        user_id: str,
        tenant_id: str,
        role_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> Optional[MemberRole]:
        stmt = select(MemberRole).where(
            MemberRole.user_id == user_id,
            MemberRole.tenant_id == tenant_id,
            MemberRole.role_id == role_id,
        )
        if scope_type is None:
            stmt = stmt.where(
                MemberRole.scope_type.is_(None), MemberRole.scope_id.is_(None)
            )
        else:
            stmt = stmt.where(
                MemberRole.scope_type == scope_type,
                MemberRole.scope_id == scope_id,
            )
        result = await self.session.execute(stmt)
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
        """TOUTES les permissions directes du membre, tous scopes confondus."""
        result = await self.session.execute(
            select(MemberPermission)
            .options(selectinload(MemberPermission.permission))
            .where(
                MemberPermission.user_id == user_id,
                MemberPermission.tenant_id == tenant_id,
            )
        )
        return list(result.scalars().all())

    async def list_in_scope(
        self,
        user_id: str,
        tenant_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> list[MemberPermission]:
        """Permissions directes d'un membre dans UN scope précis (voir MemberRoleRepository.list_in_scope)."""
        stmt = (
            select(MemberPermission)
            .options(selectinload(MemberPermission.permission))
            .where(
                MemberPermission.user_id == user_id,
                MemberPermission.tenant_id == tenant_id,
            )
        )
        if scope_type is None:
            stmt = stmt.where(
                MemberPermission.scope_type.is_(None),
                MemberPermission.scope_id.is_(None),
            )
        else:
            stmt = stmt.where(
                MemberPermission.scope_type == scope_type,
                MemberPermission.scope_id == scope_id,
            )
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def get_one(
        self,
        user_id: str,
        tenant_id: str,
        permission_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> Optional[MemberPermission]:
        stmt = select(MemberPermission).where(
            MemberPermission.user_id == user_id,
            MemberPermission.tenant_id == tenant_id,
            MemberPermission.permission_id == permission_id,
        )
        if scope_type is None:
            stmt = stmt.where(
                MemberPermission.scope_type.is_(None),
                MemberPermission.scope_id.is_(None),
            )
        else:
            stmt = stmt.where(
                MemberPermission.scope_type == scope_type,
                MemberPermission.scope_id == scope_id,
            )
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
