"""Gestion des accès d'une organisation, pour le Desk (DocTypes `Permission`, `Role`, `Member` du plugin `iam`).

Les routes HTTP de `routes/rbac.py` servent un client qui parle à xauth ; ce service sert un AUTRE plugin (le moteur de documents) qui parle POUR un
utilisateur. Il applique les MÊMES règles que les routes : une opération sur une organisation est réservée à son PROPRIÉTAIRE ou à l'administrateur de la
plateforme (`admin:*`), seules les permissions délégables (`tenant_grantable`) se distribuent, un rôle de la plateforme est en lecture seule, un rôle de
l'organisation se gère. Le plugin appelant est de confiance, mais il passe l'organisation ET l'acteur (`actor_id`) EXPLICITEMENT et c'est xauth qui juge : le
moteur autorise, xauth reste l'autorité.

Rien ici ne lit d'état ambiant (ni jeton ni ContextVar). Les erreurs sont celles de ce module (`IamForbidden`, `IamNotFound`, `IamInvalid`) : l'IPC les traduit en
code stable.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rbac import Permission, Role
from ..repositories.rbac import (
    MemberPermissionRepository,
    MemberRoleRepository,
    PermissionRepository,
    RoleRepository,
)
from ..repositories.user import TenantMemberRepository, UserRepository
from .audit import AuditService
from .rbac.members import MemberRoleService
from .rbac.permissions import PermissionService
from .rbac.roles import RoleService
from .seed import TENANT_ADMIN_ROLE

PLATFORM_ADMIN = "admin:*"
MAX_NAME = 100
MAX_DESCRIPTION = 500


class IamForbidden(Exception):
    """L'acteur n'a pas le droit (propriétaire de l'organisation ou administrateur de la plateforme)."""


class IamNotFound(Exception):
    """Un rôle ou un membre qui n'existe pas (dans cette organisation)."""


class IamInvalid(ValueError):
    """Une demande que xauth refuse : le message dit pourquoi, en français, à l'utilisateur."""


@dataclass(frozen=True, slots=True)
class Authority:
    actor_id: str
    platform_admin: bool
    owner: bool
    member: bool = False
    tenant_admin: bool = False

    @property
    def manages(self) -> bool:
        """Administrer l'organisation : la MÊME règle que les routes REST (`routes/_scope.require_tenant_admin`).

        Ce service est la seconde porte sur les mêmes opérations (les DocTypes `Member` et `Role` du plugin `iam`,
        que le Desk emploie) : si elle juge autrement, la délégation marche à l'API et pas à l'écran.
        """
        return self.platform_admin or self.owner or self.tenant_admin


def permission_dict(p: Permission) -> dict[str, Any]:
    return {
        "id": p.id, "name": p.name, "description": p.description, "source_plugin": p.source_plugin,
        "tenant_grantable": bool(p.tenant_grantable), "group": p.group, "active": bool(p.active),
    }


def role_dict(r: Role) -> dict[str, Any]:
    return {
        "id": r.id, "name": r.name, "description": r.description, "tenant_id": r.tenant_id,
        "scope": "platform" if r.tenant_id is None else "organisation",
        "permissions": sorted(p.name for p in r.permissions),
    }


def _clean_text(value: Any, what: str, limit: int, *, required: bool) -> Optional[str]:
    if value is None or (isinstance(value, str) and not value.strip()):
        if required:
            raise IamInvalid(f"{what} obligatoire")
        return None
    if not isinstance(value, str):
        raise IamInvalid(f"{what} doit être un texte")
    text = value.strip()
    if len(text) > limit:
        raise IamInvalid(f"{what} : {limit} caractères au plus")
    return text


class IamService:
    def __init__(self, session: AsyncSession, cache: Any = None) -> None:
        self._s = session
        self._cache = cache
        self._roles = RoleService(session, cache=cache)
        self._members = MemberRoleService(session, cache=cache)
        self._perms = PermissionService(session, cache=cache)

    # ── Autorité ──────────────────────────────────────────────
    async def authority(self, tenant_id: str, actor_id: str) -> Authority:
        membership = await TenantMemberRepository(self._s).get_membership(actor_id, tenant_id)
        held = await self._perms.get_permissions_for_user(actor_id, tenant_id) if membership else []
        roles = await self._members.get_roles_for_user(actor_id, tenant_id) if membership else []
        return Authority(
            actor_id,
            platform_admin=PLATFORM_ADMIN in held,
            owner=bool(membership and membership.is_owner),
            member=membership is not None,
            tenant_admin=TENANT_ADMIN_ROLE in roles,
        )

    async def _require_manage(self, tenant_id: str, actor_id: str) -> Authority:
        if not isinstance(tenant_id, str) or not tenant_id or not isinstance(actor_id, str) or not actor_id:
            raise IamForbidden("Identité ou organisation manquante")
        who = await self.authority(tenant_id, actor_id)
        if not who.manages:
            raise IamForbidden("Réservé aux administrateurs de l'organisation")
        return who

    async def _require_member(self, tenant_id: str, actor_id: str) -> Authority:
        """Un membre de l'organisation (lire l'annuaire) ; l'administrateur de la plateforme n'a pas besoin d'en être membre."""
        if not isinstance(tenant_id, str) or not tenant_id or not isinstance(actor_id, str) or not actor_id:
            raise IamForbidden("Identité ou organisation manquante")
        who = await self.authority(tenant_id, actor_id)
        if not (who.member or who.platform_admin):
            raise IamForbidden("Réservé aux membres de l'organisation")
        return who

    # ── Permissions (le catalogue) ────────────────────────────
    async def permissions(self, tenant_id: str, actor_id: str) -> list[dict[str, Any]]:
        who = await self._require_manage(tenant_id, actor_id)
        # L'administrateur de la plateforme voit tout (inactives comprises) ; le propriétaire ne voit que ce qu'il peut déléguer.
        found = await self._perms.list_permissions() if who.platform_admin else await self._perms.list_grantable_permissions()
        return [permission_dict(p) for p in sorted(found, key=lambda p: p.name)]

    # ── Rôles ─────────────────────────────────────────────────
    async def roles(self, tenant_id: str, actor_id: str) -> list[dict[str, Any]]:
        await self._require_manage(tenant_id, actor_id)
        found = await RoleRepository(self._s).list_for_tenant(tenant_id)
        return [role_dict(r) for r in sorted(found, key=lambda r: (r.tenant_id is not None, r.name.lower()))]

    async def _tenant_role(self, tenant_id: str, role_id: str) -> Role:
        role = await RoleRepository(self._s).get_with_permissions(role_id)
        if role is None or role.tenant_id not in (None, tenant_id):
            raise IamNotFound("Rôle introuvable")
        return role

    async def _grantable(self, names: list[str]) -> list[Permission]:
        repo = PermissionRepository(self._s)
        out: list[Permission] = []
        unknown: list[str] = []
        for name in dict.fromkeys(names):  # sans doublon, dans l'ordre
            perm = await repo.get_by_name(name)
            if perm is None or not perm.active or not perm.tenant_grantable:
                unknown.append(name)
            else:
                out.append(perm)
        if unknown:
            raise IamInvalid(f"Permission inconnue, inactive ou non délégable : {', '.join(sorted(unknown))}")
        return out

    async def _name_is_free(self, tenant_id: str, name: str, *, except_id: str | None = None) -> None:
        for r in await RoleRepository(self._s).list_for_tenant(tenant_id):
            if r.id != except_id and r.name.lower() == name.lower():
                raise IamInvalid("Un rôle porte déjà ce nom (de l'organisation ou de la plateforme)")

    async def role_save(self, tenant_id: str, actor_id: str, role_id: str | None, name: Any, description: Any, permissions: Any) -> dict[str, Any]:
        """Crée (`role_id` absent) ou met à jour un rôle de l'organisation : nom, description, et l'ENSEMBLE de ses permissions (le surplus est retiré)."""
        who = await self._require_manage(tenant_id, actor_id)
        label = _clean_text(name, "Le nom du rôle", MAX_NAME, required=True)
        desc = _clean_text(description, "La description", MAX_DESCRIPTION, required=False)
        if not isinstance(permissions, list) or not all(isinstance(p, str) for p in permissions or []):
            raise IamInvalid("Les permissions s'écrivent comme une liste de noms")
        role_is_platform = role_id is not None and (await self._tenant_role(tenant_id, role_id)).tenant_id is None
        # Une permission d'un rôle de l'ORGANISATION doit être délégable ; celles d'un rôle de la PLATEFORME (admin, user…) ne le sont pas toujours : voir `_save_platform_role`.
        wanted = [] if role_is_platform else await self._grantable(list(permissions or []))
        if role_id is None:
            await self._name_is_free(tenant_id, str(label))
            role = await self._roles.create_tenant_role(tenant_id, str(label), [p.name for p in wanted], description=desc)
            changes = {"created": role.name, "permissions": sorted(p.name for p in wanted)}
        else:
            role = await self._tenant_role(tenant_id, role_id)
            if role.tenant_id is None:
                changes = await self._save_platform_role(tenant_id, who, role, str(label), desc, list(permissions or []))
            else:
                if label != role.name:
                    await self._name_is_free(tenant_id, str(label), except_id=role.id)
                before = {p.name for p in role.permissions}
                role.name, role.description = str(label), desc
                after = {p.name for p in wanted}
                for gone in sorted(before - after):
                    await self._roles.remove_permission_from_tenant_role(tenant_id, role.id, gone)
                for new in sorted(after - before):
                    await self._roles.add_permission_to_tenant_role(tenant_id, role.id, new)
                await self._s.flush()
                changes = {"role": role.name, "added": sorted(after - before), "removed": sorted(before - after)}
        await AuditService(self._s).log_event(
            action="role.saved", tenant_id=tenant_id, user_id=who.actor_id, resource="role", resource_id=role.id, metadata=changes
        )
        fresh = await RoleRepository(self._s).get_with_permissions(role.id)  # même instance (identity map), ses permissions sont déjà chargées
        assert fresh is not None
        return role_dict(fresh)

    async def _save_platform_role(self, tenant_id: str, who: Authority, role: Role, label: str, desc: Optional[str], names: list[str]) -> dict[str, Any]:
        """Un rôle de la PLATEFORME (partagé par toutes les organisations) : seul l'administrateur de la plateforme le modifie, sans en changer le nom (les réglages
        d'xauth le désignent par son nom). Toute permission ACTIVE peut lui être donnée, délégable ou non."""
        if not who.platform_admin:
            raise IamInvalid("Un rôle de la plateforme ne se modifie que par l'administrateur de la plateforme")
        if label != role.name:
            raise IamInvalid("Le nom d'un rôle de la plateforme ne change pas")
        repo = PermissionRepository(self._s)
        wanted: dict[str, Permission] = {}
        for name in dict.fromkeys(names):
            perm = await repo.get_by_name(name)
            if perm is None or not perm.active:
                raise IamInvalid(f"Permission inconnue ou inactive : {name}")
            wanted[name] = perm
        before = {p.name: p for p in role.permissions}
        role.description = desc
        for gone in sorted(set(before) - set(wanted)):
            await self._roles.remove_permission_from_role(role.id, before[gone].id)
        for new in sorted(set(wanted) - set(before)):
            await self._roles.assign_permission_to_role(role.id, wanted[new].id)
        await self._s.flush()
        # Ce rôle sert toutes les organisations : on ne vide ici que le cache de celle qui demande (les autres se rafraîchissent à l'expiration du leur, 5 minutes).
        await self._roles._invalidate_tenant_cache(tenant_id)
        return {"role": role.name, "platform": True, "added": sorted(set(wanted) - set(before)), "removed": sorted(set(before) - set(wanted))}

    async def role_delete(self, tenant_id: str, actor_id: str, role_id: str) -> None:
        who = await self._require_manage(tenant_id, actor_id)
        role = await self._tenant_role(tenant_id, role_id)
        if role.tenant_id is None:
            raise IamInvalid("Un rôle de la plateforme ne se supprime pas")
        holders = await self._holders(tenant_id, role.id)
        if holders:
            raise IamInvalid(f"Ce rôle est attribué à {holders} membre(s) : retirez-le d'abord de leur fiche")
        await self._roles.delete_tenant_role(tenant_id, role.id)
        await AuditService(self._s).log_event(
            action="role.deleted", tenant_id=tenant_id, user_id=who.actor_id, resource="role", resource_id=role_id, metadata={"role": role.name}
        )

    async def _holders(self, tenant_id: str, role_id: str) -> int:
        """Combien de membres de l'organisation ont ce rôle (principal ou supplémentaire)."""
        held = set()
        for m in await TenantMemberRepository(self._s).get_members_of_tenant(tenant_id):
            if m.role_id == role_id:
                held.add(m.user_id)
        for mr in await MemberRoleRepository(self._s).list_for_role(tenant_id, role_id):
            held.add(mr.user_id)
        return len(held)

    # ── Membres ───────────────────────────────────────────────
    async def members(self, tenant_id: str, actor_id: str) -> list[dict[str, Any]]:
        """Les membres. Tout MEMBRE lit l'annuaire (qui, quelle adresse, actif ou non : de quoi lier une fiche à un compte) ; leurs rôles et permissions ne se
        voient que pour le propriétaire de l'organisation et l'administrateur de la plateforme."""
        who = await self._require_member(tenant_id, actor_id)
        return [await self._member_dict(tenant_id, m, limited=not who.manages) for m in await TenantMemberRepository(self._s).get_members_of_tenant(tenant_id)]

    async def member(self, tenant_id: str, actor_id: str, user_id: str) -> dict[str, Any]:
        who = await self._require_member(tenant_id, actor_id)
        return await self._member_dict(tenant_id, await self._membership(tenant_id, user_id), limited=not who.manages)

    async def _membership(self, tenant_id: str, user_id: str) -> Any:
        found = await TenantMemberRepository(self._s).get_membership(user_id, tenant_id)
        if found is None:
            raise IamNotFound("Membre introuvable dans cette organisation")
        return found

    async def _member_dict(self, tenant_id: str, m: Any, *, limited: bool = False) -> dict[str, Any]:
        extra: list[str] = []
        direct: list[str] = []
        if not limited:
            extra = sorted(mr.role_id for mr in await MemberRoleRepository(self._s).list_in_scope(m.user_id, tenant_id, None, None))
            direct = sorted(
                mp.permission.name for mp in await MemberPermissionRepository(self._s).list_in_scope(m.user_id, tenant_id, None, None) if mp.permission
            )
        # `m.user` n'est chargé que par `get_members_of_tenant` (selectinload) : en async un chargement paresseux est impossible, on lit le compte à part.
        user = m.__dict__.get("user") or await UserRepository(self._s).get(m.user_id)
        return {
            "user_id": m.user_id,
            "email": user.email if user else None,
            "username": user.username if user else None,
            "is_owner": bool(m.is_owner),
            "is_active": bool(user.is_active if user else True) and bool(m.user_tenant_status),
            "limited": limited,
            "primary_role_id": None if limited else m.role_id,
            "role_ids": [r for r in extra if r != m.role_id],
            "permissions": direct,
            "joined_at": m.joined_at.isoformat() if m.joined_at else None,
        }

    async def member_save(
        self, tenant_id: str, actor_id: str, user_id: str, primary_role_id: Any, role_ids: Any, permissions: Any, is_active: Any = None
    ) -> dict[str, Any]:
        """Fixe les accès d'un membre : son rôle principal, ses rôles supplémentaires et ses permissions directes. L'ENSEMBLE est donné, xauth ne
        touche qu'à la différence (un rôle de la plateforme déjà tenu se garde tel quel). Des rôles globaux, un
        administrateur d'organisation n'attribue que `tenant_admin` — c'est par là qu'il délègue l'administration
        (`RoleService._get_assignable_role`) ; les autres sont refusés, et une permission non délégable aussi."""
        who = await self._require_manage(tenant_id, actor_id)
        if primary_role_id is not None and not isinstance(primary_role_id, str):
            raise IamInvalid("Le rôle principal est un identifiant de rôle")
        for name, value in (("role_ids", role_ids), ("permissions", permissions)):
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value or []):
                raise IamInvalid(f"{name} s'écrit comme une liste de textes")
        m = await self._membership(tenant_id, user_id)
        before = await self._member_dict(tenant_id, m)
        want_primary = primary_role_id or None
        want_extra = [r for r in dict.fromkeys(role_ids or []) if r != want_primary]
        want_perms = list(dict.fromkeys(permissions or []))

        add_roles = [r for r in want_extra if r not in before["role_ids"]]
        drop_roles = [r for r in before["role_ids"] if r not in want_extra]
        add_perms = [p for p in want_perms if p not in before["permissions"]]
        drop_perms = [p for p in before["permissions"] if p not in want_perms]
        primary_changed = want_primary != before["primary_role_id"]
        if is_active is not None and not isinstance(is_active, bool):
            raise IamInvalid("is_active est un booléen")
        status_changed = is_active is not None and is_active != before["is_active"]
        if status_changed and (m.is_owner or user_id == who.actor_id):
            raise IamInvalid("Le propriétaire de l'organisation et vous-même ne pouvez pas être désactivés ici")
        removes_access = bool(drop_roles or drop_perms or (primary_changed and before["primary_role_id"] is not None))
        if user_id == who.actor_id and not who.platform_admin and (removes_access or primary_changed):
            raise IamInvalid("Vous ne pouvez pas retirer ni changer vos propres accès : demandez-le à un autre administrateur")

        if primary_changed:
            if want_primary is None:
                m.role_id = None
                await self._s.flush()
                await self._members._invalidate_cache(user_id, tenant_id)
            else:
                await self._roles.assign_role_to_member(user_id, tenant_id, want_primary)  # ValueError : « n'appartient pas à votre tenant »
        if status_changed:
            m.user_tenant_status = bool(is_active)  # désactivé dans CETTE organisation seulement (le compte, lui, reste actif ailleurs)
            await self._s.flush()
            await self._members._invalidate_cache(user_id, tenant_id)
        for role_id in add_roles:
            await self._members.add_role_to_member(user_id, tenant_id, role_id, granted_by=who.actor_id)
        for role_id in drop_roles:
            await self._members.remove_role_from_member(user_id, tenant_id, role_id)
        for name in add_perms:
            await self._perms.grant_permission_to_member(user_id, tenant_id, name, granted_by=who.actor_id)
        for name in drop_perms:
            await self._perms.revoke_permission_from_member(user_id, tenant_id, name)
        if primary_changed or status_changed or add_roles or drop_roles or add_perms or drop_perms:
            await AuditService(self._s).log_event(
                action="member.access_changed", tenant_id=tenant_id, user_id=who.actor_id, resource="tenant_member", resource_id=user_id,
                metadata={"primary": [before["primary_role_id"], want_primary] if primary_changed else None, "roles_added": add_roles,
                          "roles_removed": drop_roles, "permissions_added": add_perms, "permissions_removed": drop_perms,
                          "active": is_active if status_changed else None},
            )
        await self._s.flush()
        return await self._member_dict(tenant_id, await self._membership(tenant_id, user_id))

    async def member_remove(self, tenant_id: str, actor_id: str, user_id: str) -> None:
        who = await self._require_manage(tenant_id, actor_id)
        m = await self._membership(tenant_id, user_id)
        if m.is_owner:
            raise IamInvalid("Impossible de retirer le propriétaire de l'organisation")
        if user_id == who.actor_id:
            raise IamInvalid("Vous ne pouvez pas vous retirer vous-même")
        await TenantMemberRepository(self._s).delete(m)
        await AuditService(self._s).log_event(
            action="tenant.member_removed", tenant_id=tenant_id, user_id=who.actor_id, resource="tenant_member", resource_id=user_id
        )
        await self._members._invalidate_cache(user_id, tenant_id)

    async def user_summary(self, tenant_id: str, actor_id: str, user_id: str) -> dict[str, Any] | None:
        """Qui est ce compte (e-mail, nom), s'il est membre de l'organisation : pour relier une fiche à un compte."""
        await self._require_manage(tenant_id, actor_id)
        if await TenantMemberRepository(self._s).get_membership(user_id, tenant_id) is None:
            return None
        user = await UserRepository(self._s).get(user_id)
        return {"user_id": user_id, "email": user.email, "username": user.username} if user else None
