from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.rbac import MemberPermission, Permission
from ...repositories.rbac import (
    MemberPermissionRepository,
    MemberRoleRepository,
    PermissionRepository,
    RoleRepository,
)
from ...repositories.user import TenantMemberRepository

logger = get_logger("xauth.rbac.permissions")

_PERM_CACHE_TTL = 300


class PermissionService:
    def __init__(self, session: AsyncSession, cache: Any = None) -> None:
        self._session = session
        self._cache = cache

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

    async def get_permissions_for_user(
        self,
        user_id: str,
        tenant_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> list[str]:
        scoped = scope_type is not None
        cache_key = f"xauth:perms:{user_id}:{tenant_id}"

        if self._cache and not scoped:
            try:
                cached = await self._cache.get(cache_key)
                if cached:
                    return json.loads(cached)
            except Exception:
                pass

        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership is None:
            return []

        role_repo = RoleRepository(self._session)
        member_role_repo = MemberRoleRepository(self._session)
        member_perm_repo = MemberPermissionRepository(self._session)

        role_ids: set[str] = set()
        if membership.role_id:
            role_ids.add(membership.role_id)
        for mr in await member_role_repo.list_in_scope(user_id, tenant_id):
            role_ids.add(mr.role_id)

        names: set[str] = set()
        for mp in await member_perm_repo.list_in_scope(user_id, tenant_id):
            if mp.permission and mp.permission.active:
                names.add(mp.permission.name)

        if scoped:
            for mr in await member_role_repo.list_in_scope(
                user_id, tenant_id, scope_type, scope_id
            ):
                role_ids.add(mr.role_id)
            for mp in await member_perm_repo.list_in_scope(
                user_id, tenant_id, scope_type, scope_id
            ):
                if mp.permission and mp.permission.active:
                    names.add(mp.permission.name)

        for rid in role_ids:
            role = await role_repo.get_with_permissions(rid)
            if role is not None:
                names.update(p.name for p in role.permissions if p.active)

        permissions = sorted(names)

        if self._cache and not scoped:
            try:
                await self._cache.set(
                    cache_key, json.dumps(permissions), ex=_PERM_CACHE_TTL
                )
            except Exception:
                pass

        return permissions

    async def has_permission(
        self,
        user_id: str,
        tenant_id: str,
        permission: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> bool:
        permissions = await self.get_permissions_for_user(
            user_id, tenant_id, scope_type, scope_id
        )
        return permission in permissions

    async def list_grantable_permissions(
        self, entitled_plugins: Optional[set[str]] = None
    ) -> list[Permission]:
        perms = await PermissionRepository(self._session).list_grantable()
        if entitled_plugins is not None:
            perms = [
                p
                for p in perms
                if p.source_plugin is None or p.source_plugin in entitled_plugins
            ]
        return perms

    async def grant_permission_to_member(
        self,
        user_id: str,
        tenant_id: str,
        permission_name: str,
        granted_by: Optional[str] = None,
        entitled_plugins: Optional[set[str]] = None,
    ) -> MemberPermission:
        perm_repo = PermissionRepository(self._session)
        perm = await perm_repo.get_by_name(permission_name)
        if perm is None or not perm.active:
            raise ValueError("Permission inconnue ou inactive")
        if not perm.tenant_grantable:
            raise ValueError("Cette permission n'est pas délégable par un tenant")
        if (
            entitled_plugins is not None
            and perm.source_plugin is not None
            and perm.source_plugin not in entitled_plugins
        ):
            raise ValueError("Le tenant n'a pas accès à ce plugin (entitlement)")

        member_repo = TenantMemberRepository(self._session)
        if await member_repo.get_membership(user_id, tenant_id) is None:
            raise ValueError("L'utilisateur n'est pas membre de ce tenant")

        mp_repo = MemberPermissionRepository(self._session)
        existing = await mp_repo.get_one(user_id, tenant_id, perm.id)
        if existing is not None:
            return existing

        mp = MemberPermission(
            user_id=user_id,
            tenant_id=tenant_id,
            permission_id=perm.id,
            granted_by=granted_by,
        )
        saved = await mp_repo.save(mp)
        await self._invalidate_cache(user_id, tenant_id)
        logger.info("Permission '%s' granted to user %s in tenant %s", permission_name, user_id, tenant_id)
        return saved

    async def revoke_permission_from_member(
        self, user_id: str, tenant_id: str, permission_name: str
    ) -> bool:
        perm = await PermissionRepository(self._session).get_by_name(permission_name)
        if perm is None:
            return False
        mp_repo = MemberPermissionRepository(self._session)
        existing = await mp_repo.get_one(user_id, tenant_id, perm.id)
        if existing is None:
            return False
        await mp_repo.delete(existing)
        await self._invalidate_cache(user_id, tenant_id)
        return True

    async def _invalidate_cache(self, user_id: str, tenant_id: str) -> None:
        if self._cache:
            cache_key = f"xauth:perms:{user_id}:{tenant_id}"
            try:
                await self._cache.delete(cache_key)
            except Exception:
                pass
