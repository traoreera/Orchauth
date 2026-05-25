from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rbac import Role, Permission
from ..models.user import TenantMember
from ..repositories.rbac import RoleRepository, PermissionRepository
from ..repositories.user import TenantMemberRepository


_PERM_CACHE_TTL = 300
_CACHE_KEY_TPL = "xauth:perms:{user_id}:{tenant_id}"


class RBACService:
    def __init__(self, session: AsyncSession, cache: Any = None) -> None:
        self._session = session
        self._cache = cache

    async def create_role(
        self,
        name: str,
        tenant_id: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Role:
        repo = RoleRepository(self._session)
        role = Role(name=name, tenant_id=tenant_id, description=description)
        return await repo.save(role)

    async def get_role(self, role_id: str) -> Optional[Role]:
        repo = RoleRepository(self._session)
        return await repo.get_with_permissions(role_id)

    async def list_roles(self, tenant_id: Optional[str] = None) -> list[Role]:
        repo = RoleRepository(self._session)
        return await repo.list_for_tenant(tenant_id)

    async def create_permission(
        self, name: str, description: Optional[str] = None
    ) -> Permission:
        repo = PermissionRepository(self._session)
        perm = Permission(name=name, description=description)
        return await repo.save(perm)

    async def get_permission(self, permission_id: str) -> Optional[Permission]:
        repo = PermissionRepository(self._session)
        return await repo.get(permission_id)

    async def list_permissions(self) -> list[Permission]:
        repo = PermissionRepository(self._session)
        return await repo.all()

    async def assign_permission_to_role(
        self, role_id: str, permission_id: str
    ) -> Role:
        role_repo = RoleRepository(self._session)
        perm_repo = PermissionRepository(self._session)

        role = await role_repo.get_with_permissions(role_id)
        if role is None:
            raise ValueError(f"Role {role_id} not found")

        perm = await perm_repo.get(permission_id)
        if perm is None:
            raise ValueError(f"Permission {permission_id} not found")

        if perm not in role.permissions:
            role.permissions.append(perm)
            await self._session.flush()

        return role

    async def remove_permission_from_role(
        self, role_id: str, permission_id: str
    ) -> Role:
        role_repo = RoleRepository(self._session)
        perm_repo = PermissionRepository(self._session)

        role = await role_repo.get_with_permissions(role_id)
        if role is None:
            raise ValueError(f"Role {role_id} not found")

        perm = await perm_repo.get(permission_id)
        if perm and perm in role.permissions:
            role.permissions.remove(perm)
            await self._session.flush()

        return role

    async def assign_role_to_member(
        self, user_id: str, tenant_id: str, role_id: str
    ) -> TenantMember:
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership is None:
            raise ValueError("User is not a member of this tenant")

        membership.role_id = role_id
        await self._session.flush()

        # Invalidate cache
        await self._invalidate_cache(user_id, tenant_id)
        return membership

    async def get_permissions_for_user(
        self, user_id: str, tenant_id: str
    ) -> list[str]:
        # Try cache first
        cache_key = _CACHE_KEY_TPL.format(user_id=user_id, tenant_id=tenant_id)
        if self._cache:
            try:
                cached = await self._cache.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        # Load from DB
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership is None or membership.role_id is None:
            return []

        role_repo = RoleRepository(self._session)
        role = await role_repo.get_with_permissions(membership.role_id)
        if role is None:
            return []

        permissions = [p.name for p in role.permissions]

        # Store in cache
        if self._cache:
            try:
                await self._cache.set(cache_key, json.dumps(permissions), ex=_PERM_CACHE_TTL)
            except Exception:
                pass

        return permissions

    async def get_roles_for_user(self, user_id: str, tenant_id: str) -> list[str]:
        """Retourne les noms des rôles de l'utilisateur dans le tenant."""
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership is None or membership.role_id is None:
            return []
        role_repo = RoleRepository(self._session)
        role = await role_repo.get(membership.role_id)
        if role is None:
            return []

        return [role.name]

    async def has_permission(
        self, user_id: str, tenant_id: str, permission: str
    ) -> bool:
        permissions = await self.get_permissions_for_user(user_id, tenant_id)
        return permission in permissions

    async def _invalidate_cache(self, user_id: str, tenant_id: str) -> None:
        if self._cache:
            cache_key = _CACHE_KEY_TPL.format(user_id=user_id, tenant_id=tenant_id)
            try:
                await self._cache.delete(cache_key)
            except Exception:
                pass
