from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.rbac import MemberRole
from ...repositories.rbac import MemberRoleRepository, RoleRepository
from ...repositories.user import TenantMemberRepository

logger = get_logger("xauth.rbac.members")


class MemberRoleService:
    def __init__(self, session: AsyncSession, cache: Any = None) -> None:
        self._session = session
        self._cache = cache

    async def get_roles_for_user(self, user_id: str, tenant_id: str) -> list[str]:
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership is None:
            return []

        role_repo = RoleRepository(self._session)
        names: list[str] = []

        if membership.role_id:
            role = await role_repo.get(membership.role_id)
            if role is not None:
                names.append(role.name)

        mr_repo = MemberRoleRepository(self._session)
        for mr in await mr_repo.list_for_member(user_id, tenant_id):
            role = await role_repo.get(mr.role_id)
            if role is not None and role.name not in names:
                names.append(role.name)

        return names

    async def add_role_to_member(
        self,
        user_id: str,
        tenant_id: str,
        role_id: str,
        granted_by: Optional[str] = None,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> MemberRole:
        from .roles import RoleService

        role_svc = RoleService(self._session, self._cache)
        await role_svc._get_owned_role(tenant_id, role_id)

        member_repo = TenantMemberRepository(self._session)
        if await member_repo.get_membership(user_id, tenant_id) is None:
            raise ValueError("L'utilisateur n'est pas membre de ce tenant")

        mr_repo = MemberRoleRepository(self._session)
        existing = await mr_repo.get_one(
            user_id, tenant_id, role_id, scope_type, scope_id
        )
        if existing is not None:
            return existing
        mr = MemberRole(
            user_id=user_id,
            tenant_id=tenant_id,
            role_id=role_id,
            granted_by=granted_by,
            scope_type=scope_type,
            scope_id=scope_id,
        )
        saved = await mr_repo.save(mr)
        await self._invalidate_cache(user_id, tenant_id)
        return saved

    async def remove_role_from_member(
        self,
        user_id: str,
        tenant_id: str,
        role_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> bool:
        mr_repo = MemberRoleRepository(self._session)
        existing = await mr_repo.get_one(
            user_id, tenant_id, role_id, scope_type, scope_id
        )
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        touched = False
        if existing is not None:
            await mr_repo.delete(existing)
            touched = True
        if (
            scope_type is None
            and membership is not None
            and membership.role_id == role_id
        ):
            membership.role_id = None
            touched = True
        if touched:
            await self._invalidate_cache(user_id, tenant_id)
        return touched

    async def list_member_roles(self, user_id: str, tenant_id: str) -> list[str]:
        ids: set[str] = set()
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership and membership.role_id:
            ids.add(membership.role_id)
        mr_repo = MemberRoleRepository(self._session)
        for mr in await mr_repo.list_for_member(user_id, tenant_id):
            ids.add(mr.role_id)
        return sorted(ids)

    async def list_roles_in_scope(
        self,
        user_id: str,
        tenant_id: str,
        scope_type: Optional[str] = None,
        scope_id: Optional[str] = None,
    ) -> list[str]:
        """Rôles d'un membre pour UN scope précis (ex. scope_type="branch",
        scope_id=<branch_id>) — contrairement à `list_member_roles`, ne
        fusionne pas tous les scopes : nécessaire pour révoquer précisément
        les rôles liés à une ressource donnée (ex. retrait d'une branche)
        sans toucher aux rôles globaux ou scopés ailleurs."""
        mr_repo = MemberRoleRepository(self._session)
        return sorted({
            mr.role_id
            for mr in await mr_repo.list_in_scope(user_id, tenant_id, scope_type, scope_id)
        })

    async def list_tenant_members(self, tenant_id: str) -> list[dict]:
        member_repo = TenantMemberRepository(self._session)
        mr_repo = MemberRoleRepository(self._session)
        members = await member_repo.get_members_of_tenant(tenant_id)
        out: list[dict] = []
        for m in members:
            role_ids: set[str] = set()
            if m.role_id:
                role_ids.add(m.role_id)
            for mr in await mr_repo.list_for_member(m.user_id, tenant_id):
                role_ids.add(mr.role_id)
            out.append(
                {
                    "user_id": m.user_id,
                    "email": m.user.email if m.user else None,
                    "primary_role_id": m.role_id,
                    "role_ids": sorted(role_ids),
                    "is_owner": m.is_owner,
                }
            )
        return out

    async def _invalidate_cache(self, user_id: str, tenant_id: str) -> None:
        if self._cache:
            cache_key = f"xauth:perms:{user_id}:{tenant_id}"
            try:
                await self._cache.delete(cache_key)
            except Exception:
                pass
