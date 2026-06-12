from __future__ import annotations

import json
import re
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rbac import MemberPermission, MemberRole, Permission, Role
from ..models.user import TenantMember
from ..repositories.rbac import (
    MemberPermissionRepository,
    MemberRoleRepository,
    PermissionRepository,
    RoleRepository,
)
from ..repositories.user import TenantMemberRepository

_PERM_CACHE_TTL = 300
_CACHE_KEY_TPL = "xauth:perms:{user_id}:{tenant_id}"

# ── Contrat d'agrégation des grants plugins (event rbac.declare) ───────────────
# Un plugin ne peut déclarer QUE dans son propre namespace, jamais un namespace
# plateforme. C'est le verrou de sécurité de l'agrégation.
RESERVED_NAMESPACES = {"admin", "rbac", "auth", "tenants", "user", "license", "plugins"}
_GRANT_NAME_RE = re.compile(r"^[a-z0-9_]+:[a-z0-9_]+(:[a-z0-9_]+)*$")


def _is_valid_grant(plugin: str, name: str) -> bool:
    """name doit être préfixé par <plugin>: et hors namespace réservé."""
    if plugin in RESERVED_NAMESPACES:
        return False
    if not name or not _GRANT_NAME_RE.match(name):
        return False
    return name.split(":", 1)[0] == plugin


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

    async def get_permissions_for_user(self, user_id: str, tenant_id: str) -> list[str]:
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
        if membership is None:
            return []

        # Résolution = union de TOUS les rôles (multi-rôles member_roles + rôle
        # primaire legacy role_id) ∪ permissions directes du membre. Actives only.
        names: set[str] = set()
        role_repo = RoleRepository(self._session)

        role_ids: set[str] = set()
        if membership.role_id:
            role_ids.add(membership.role_id)  # rôle primaire (seed/invites)
        member_role_repo = MemberRoleRepository(self._session)
        for mr in await member_role_repo.list_for_member(user_id, tenant_id):
            role_ids.add(mr.role_id)

        for rid in role_ids:
            role = await role_repo.get_with_permissions(rid)
            if role is not None:
                names.update(p.name for p in role.permissions if p.active)

        member_perm_repo = MemberPermissionRepository(self._session)
        for mp in await member_perm_repo.list_for_member(user_id, tenant_id):
            if mp.permission and mp.permission.active:
                names.add(mp.permission.name)

        permissions = sorted(names)

        # Store in cache
        if self._cache:
            try:
                await self._cache.set(
                    cache_key, json.dumps(permissions), ex=_PERM_CACHE_TTL
                )
            except Exception:
                pass

        return permissions

    async def get_roles_for_user(self, user_id: str, tenant_id: str) -> list[str]:
        """Retourne les noms des rôles de l'utilisateur dans le tenant (rôle primaire + multi-rôles)."""
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

    # ── Agrégation des grants plugins (consommé par les events) ───────────────

    async def reconcile_plugin_grants(
        self, plugin: str, grants: list[dict]
    ) -> dict[str, int]:
        """Synchronise le catalogue avec les grants déclarés par un plugin.

        Déclaratif & idempotent : `grants` = état complet du plugin. Upsert des
        grants valides, soft-disable de ceux qui ont disparu. Renvoie un compte.
        """
        perm_repo = PermissionRepository(self._session)
        desired: dict[str, dict] = {}
        for g in grants or []:
            name = (g or {}).get("name")
            if _is_valid_grant(plugin, name):
                desired[name] = g

        upserted = 0
        for name, g in desired.items():
            perm = await perm_repo.get_by_name(name)
            if perm is None:
                perm = Permission(name=name)
            perm.description = g.get("description")
            perm.group = g.get("group")
            perm.tenant_grantable = bool(g.get("tenant_grantable", False))
            perm.source_plugin = plugin
            perm.active = True
            await perm_repo.save(perm)
            upserted += 1
        disabled = 0
        for perm in await perm_repo.list_by_plugin(plugin):
            if perm.name not in desired and perm.active:
                perm.active = False
                await perm_repo.save(perm)
                disabled += 1

        return {"upserted": upserted, "disabled": disabled}

    async def disable_plugin(self, plugin: str) -> int:
        """Soft-disable toutes les permissions d'un plugin retiré."""
        perm_repo = PermissionRepository(self._session)
        count = 0
        for perm in await perm_repo.list_by_plugin(plugin):
            if perm.active:
                perm.active = False
                await perm_repo.save(perm)
                count += 1
        return count

    # ── Surface owner (tenant-scopée) ─────────────────────────────────────────

    async def list_grantable_permissions(
        self, entitled_plugins: Optional[set[str]] = None
    ) -> list[Permission]:
        """Permissions qu'un owner peut déléguer : actives & tenant_grantable,
        et (si fourni) restreintes aux plugins auxquels le tenant a droit."""
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
        """Accorde une permission délégable à un membre du tenant (toggle owner)."""
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

    async def create_tenant_role(
        self,
        tenant_id: str,
        name: str,
        permission_names: list[str],
        description: Optional[str] = None,
        entitled_plugins: Optional[set[str]] = None,
    ) -> Role:
        """Crée un rôle PROPRE au tenant, en n'attachant que des permissions
        délégables (et dans l'entitlement si fourni). tenant_id forcé."""
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
        """Rôles PROPRES au tenant (exclut les rôles globaux plateforme)."""
        repo = RoleRepository(self._session)
        roles = await repo.list_for_tenant(tenant_id)
        out: list[Role] = []
        for r in roles:
            if r.tenant_id != tenant_id:
                continue  # ignore les rôles globaux (tenant_id None)
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
        mr_repo = MemberRoleRepository(self._session)
        # Détache le rôle primaire (role_id legacy) des membres qui le portent.
        for m in await member_repo.get_members_of_tenant(tenant_id):
            if m.role_id == role_id:
                m.role_id = None
                await self._invalidate_cache(m.user_id, tenant_id)
        # Détache les assignations multi-rôles (member_roles) pointant ce rôle.
        for mr in await mr_repo.list_for_role(tenant_id, role_id):
            await self._invalidate_cache(mr.user_id, tenant_id)
            await mr_repo.delete(mr)
        await RoleRepository(self._session).delete(role)

    # ── Multi-rôles : assignation de plusieurs rôles à un membre ──────────────

    async def add_role_to_member(
        self,
        user_id: str,
        tenant_id: str,
        role_id: str,
        granted_by: Optional[str] = None,
    ) -> MemberRole:
        """Ajoute un rôle (du tenant) à un membre, en plus de ses rôles existants."""
        await self._get_owned_role(tenant_id, role_id)  # rôle du tenant ou 403
        member_repo = TenantMemberRepository(self._session)
        if await member_repo.get_membership(user_id, tenant_id) is None:
            raise ValueError("L'utilisateur n'est pas membre de ce tenant")

        mr_repo = MemberRoleRepository(self._session)
        existing = await mr_repo.get_one(user_id, tenant_id, role_id)
        if existing is not None:
            return existing
        mr = MemberRole(
            user_id=user_id,
            tenant_id=tenant_id,
            role_id=role_id,
            granted_by=granted_by,
        )
        saved = await mr_repo.save(mr)
        await self._invalidate_cache(user_id, tenant_id)
        return saved

    async def remove_role_from_member(
        self, user_id: str, tenant_id: str, role_id: str
    ) -> bool:
        mr_repo = MemberRoleRepository(self._session)
        existing = await mr_repo.get_one(user_id, tenant_id, role_id)
        # Permet aussi de retirer un rôle primaire legacy (role_id sur le membre).
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        touched = False
        if existing is not None:
            await mr_repo.delete(existing)
            touched = True
        if membership is not None and membership.role_id == role_id:
            membership.role_id = None
            touched = True
        if touched:
            await self._invalidate_cache(user_id, tenant_id)
        return touched

    async def list_member_roles(self, user_id: str, tenant_id: str) -> list[str]:
        """IDs des rôles d'un membre (primaire legacy + multi-rôles)."""
        ids: set[str] = set()
        member_repo = TenantMemberRepository(self._session)
        membership = await member_repo.get_membership(user_id, tenant_id)
        if membership and membership.role_id:
            ids.add(membership.role_id)
        mr_repo = MemberRoleRepository(self._session)
        for mr in await mr_repo.list_for_member(user_id, tenant_id):
            ids.add(mr.role_id)
        return sorted(ids)

    async def list_tenant_members(self, tenant_id: str) -> list[dict]:
        """Membres du tenant avec TOUS leurs rôles (pour l'UI owner)."""
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

    async def _invalidate_tenant_cache(self, tenant_id: str) -> None:
        """Invalide le cache perms de tous les membres du tenant (rôle modifié)."""
        member_repo = TenantMemberRepository(self._session)
        for m in await member_repo.get_members_of_tenant(tenant_id):
            await self._invalidate_cache(m.user_id, tenant_id)
