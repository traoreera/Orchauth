from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.rbac import Role
from ...repositories.rbac import PermissionRepository, RoleRepository
from ...repositories.user import TenantMemberRepository

logger = get_logger("xauth.rbac.roles")


class RoleService:
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

    async def assign_permission_to_role(self, role_id: str, permission_id: str) -> Role:
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
    ) -> Any:
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership is None:
            raise ValueError("User is not a member of this tenant")

        await self._get_owned_role(tenant_id, role_id)

        membership.role_id = role_id
        await self._session.flush()
        await self._invalidate_cache(user_id, tenant_id)
        logger.info("Role '%s' assigned to user %s in tenant %s", role_id, user_id, tenant_id)
        return membership

    async def create_tenant_role(
        self,
        tenant_id: str,
        name: str,
        permission_names: list[str],
        description: Optional[str] = None,
        entitled_plugins: Optional[set[str]] = None,
    ) -> Role:
        perm_repo = PermissionRepository(self._session)
        role_repo = RoleRepository(self._session)
        role = Role(name=name, tenant_id=tenant_id, description=description)
        role = await role_repo.save(role)
        role = await role_repo.get_with_permissions(role.id)

        for pname in permission_names or []:
            perm = await perm_repo.get_by_name(pname)
            if perm is None or not perm.active or not perm.tenant_grantable:
                continue
            if (
                entitled_plugins is not None
                and perm.source_plugin is not None
                and perm.source_plugin not in entitled_plugins
            ):
                continue
            if perm not in role.permissions:
                role.permissions.append(perm)
        await self._session.flush()
        return role

    async def list_tenant_roles(self, tenant_id: str) -> list[Role]:
        repo = RoleRepository(self._session)
        roles = await repo.list_for_tenant(tenant_id)
        out: list[Role] = []
        for r in roles:
            if r.tenant_id != tenant_id:
                continue
            out.append(await repo.get_with_permissions(r.id))
        return out

    async def _get_owned_role(self, tenant_id: str, role_id: str) -> Role:
        role = await RoleRepository(self._session).get_with_permissions(role_id)
        if role is None:
            raise ValueError("Rôle introuvable")
        if role.tenant_id != tenant_id:
            raise ValueError("Ce rôle n'appartient pas à votre tenant")
        return role

    async def add_permission_to_tenant_role(
        self,
        tenant_id: str,
        role_id: str,
        permission_name: str,
        entitled_plugins: Optional[set[str]] = None,
    ) -> Role:
        role = await self._get_owned_role(tenant_id, role_id)
        perm = await PermissionRepository(self._session).get_by_name(permission_name)
        if perm is None or not perm.active or not perm.tenant_grantable:
            raise ValueError("Permission inconnue, inactive ou non délégable")
        if (
            entitled_plugins is not None
            and perm.source_plugin is not None
            and perm.source_plugin not in entitled_plugins
        ):
            raise ValueError("Le tenant n'a pas accès à ce plugin (entitlement)")
        if perm not in role.permissions:
            role.permissions.append(perm)
            await self._session.flush()
        await self._invalidate_tenant_cache(tenant_id)
        return role

    async def remove_permission_from_tenant_role(
        self, tenant_id: str, role_id: str, permission_name: str
    ) -> Role:
        role = await self._get_owned_role(tenant_id, role_id)
        perm = await PermissionRepository(self._session).get_by_name(permission_name)
        if perm and perm in role.permissions:
            role.permissions.remove(perm)
            await self._session.flush()
        await self._invalidate_tenant_cache(tenant_id)
        return role

    async def delete_tenant_role(self, tenant_id: str, role_id: str) -> None:
        role = await self._get_owned_role(tenant_id, role_id)
        member_repo = TenantMemberRepository(self._session)
        from ...repositories.rbac import MemberRoleRepository

        mr_repo = MemberRoleRepository(self._session)
        for m in await member_repo.get_members_of_tenant(tenant_id):
            if m.role_id == role_id:
                m.role_id = None
                await self._invalidate_cache(m.user_id, tenant_id)
        for mr in await mr_repo.list_for_role(tenant_id, role_id):
            await self._invalidate_cache(mr.user_id, tenant_id)
            await mr_repo.delete(mr)
        await RoleRepository(self._session).delete(role)

    async def _invalidate_cache(self, user_id: str, tenant_id: str) -> None:
        if self._cache:
            cache_key = f"xauth:perms:{user_id}:{tenant_id}"
            try:
                await self._cache.delete(cache_key)
            except Exception:
                pass

    async def _invalidate_tenant_cache(self, tenant_id: str) -> None:
        if self._cache:
            member_repo = TenantMemberRepository(self._session)
            for m in await member_repo.get_members_of_tenant(tenant_id):
                await self._invalidate_cache(m.user_id, tenant_id)
