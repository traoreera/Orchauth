from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from ..models.rbac import Permission, Role
from ..models.tenant import Tenant
from ..models.user import TenantMember, User
from ..repositories.rbac import PermissionRepository, RoleRepository
from ..repositories.tenant import TenantRepository
from ..repositories.user import TenantMemberRepository, UserRepository
from .auth import get_pwd_context

logger = logging.getLogger("xauth.seed")

# ── Catalogue de permissions ──────────────────────────────────────────────────
#
# tenant_grantable=True  → le propriétaire d'un tenant peut déléguer cette
#                          permission à ses membres via l'UI RBAC.
# group                  → regroupement affiché dans l'UI.


@dataclass(frozen=True)
class PermDef:
    name: str
    description: str
    group: str
    tenant_grantable: bool = False


PERMISSIONS: list[PermDef] = [
    # ── Plugins ───────────────────────────────────────────────────────────────
    PermDef("plugin:list", "Lister les plugins", "Plugins", tenant_grantable=True),
    PermDef("plugin:read", "Lire un plugin", "Plugins", tenant_grantable=True),
    PermDef("plugin:create", "Publier un plugin", "Plugins"),
    PermDef("plugin:update", "Modifier un plugin", "Plugins"),
    PermDef("plugin:delete", "Supprimer un plugin", "Plugins"),
    PermDef("plugin:approve", "Approuver un plugin", "Plugins"),
    PermDef("plugin:reject", "Rejeter un plugin", "Plugins"),
    PermDef("plugin:feature", "Mettre en avant un plugin", "Plugins"),
    # ── Soumissions ───────────────────────────────────────────────────────────
    PermDef(
        "submissions:list",
        "Lister les soumissions",
        "Soumissions",
        tenant_grantable=True,
    ),
    PermDef(
        "submissions:read", "Lire une soumission", "Soumissions", tenant_grantable=True
    ),
    PermDef(
        "submissions:create",
        "Créer une soumission",
        "Soumissions",
        tenant_grantable=True,
    ),
    PermDef(
        "submissions:write",
        "Poster un nouveau plugin",
        "Soumissions",
        tenant_grantable=True,
    ),
    PermDef("submissions:review", "Réviser une soumission", "Soumissions"),
    PermDef("submissions:approve", "Approuver une soumission", "Soumissions"),
    PermDef("submissions:reject", "Rejeter une soumission", "Soumissions"),
    PermDef("submissions:delete", "Supprimer une soumission", "Soumissions"),
    # ── Évaluations ───────────────────────────────────────────────────────────
    PermDef(
        "rating:create", "Créer une évaluation", "Évaluations", tenant_grantable=True
    ),
    PermDef("rating:delete", "Supprimer une évaluation", "Évaluations"),
    # ── Utilisateurs ──────────────────────────────────────────────────────────
    PermDef("user:list", "Lister les utilisateurs", "Utilisateurs"),
    PermDef("user:read", "Lire un utilisateur", "Utilisateurs", tenant_grantable=True),
    PermDef("user:update", "Modifier un utilisateur", "Utilisateurs"),
    PermDef("user:delete", "Supprimer un utilisateur", "Utilisateurs"),
    PermDef("user:ban", "Bannir un utilisateur", "Utilisateurs"),
    # ── Tenants ───────────────────────────────────────────────────────────────
    PermDef("tenant:list", "Lister les tenants", "Tenants"),
    PermDef("tenant:read", "Lire un tenant", "Tenants"),
    PermDef("tenant:create", "Créer un tenant", "Tenants"),
    PermDef("tenant:update", "Modifier un tenant", "Tenants"),
    PermDef("tenant:delete", "Supprimer un tenant", "Tenants"),
    PermDef(
        "tenants:read",
        "Lire les tenants (routes API)",
        "Tenants",
        tenant_grantable=True,
    ),
    PermDef("tenants:write", "Modifier les tenants (routes API)", "Tenants"),
    PermDef("tenants:delete", "Supprimer les tenants (routes API)", "Tenants"),
    # ── RBAC ──────────────────────────────────────────────────────────────────
    PermDef("role:list", "Lister les rôles", "RBAC"),
    PermDef("role:create", "Créer un rôle", "RBAC"),
    PermDef("role:update", "Modifier un rôle", "RBAC"),
    PermDef("role:delete", "Supprimer un rôle", "RBAC"),
    PermDef("permission:list", "Lister les permissions", "RBAC"),
    PermDef("permission:assign", "Assigner une permission", "RBAC"),
    PermDef(
        "rbac:read",
        "Lire les rôles et permissions (routes API)",
        "RBAC",
        tenant_grantable=True,
    ),
    PermDef("rbac:write", "Modifier les rôles et permissions (routes API)", "RBAC"),
    # ── Audit ─────────────────────────────────────────────────────────────────
    PermDef("audit:read", "Lire les logs d'audit", "Audit", tenant_grantable=True),
    # ── Invitations ───────────────────────────────────────────────────────────
    PermDef("invite:create", "Créer une invitation", "Invitations"),
    PermDef("invite:revoke", "Révoquer une invitation", "Invitations"),
    PermDef(
        "invites:read",
        "Lire les invitations (routes API)",
        "Invitations",
        tenant_grantable=True,
    ),
    PermDef(
        "invites:write",
        "Gérer les invitations (routes API)",
        "Invitations",
        tenant_grantable=True,
    ),
    # ── Licences ──────────────────────────────────────────────────────────────
    PermDef("license:read", "Lire les licences", "Licences", tenant_grantable=True),
    PermDef("license:write", "Modifier les licences", "Licences"),
    PermDef("license:manage", "Gérer les licences", "Licences"),
    # ── Notifications (xpulse) ────────────────────────────────────────────────
    PermDef("xpulse:publish", "Publier un message ciblé via xpulse", "Notifications"),
    PermDef(
        "xpulse:broadcast", "Broadcaster un message à tous les users", "Notifications"
    ),
    # ── Administration plateforme ─────────────────────────────────────────────
    PermDef(
        "admin:*",
        "Accès administrateur complet à toutes les ressources",
        "Administration",
    ),
]

# ── Composition des rôles ─────────────────────────────────────────────────────
# Déclaratif : la seed synchronise exactement ces listes (ajout ET retrait).

# Permissions accordées à tout utilisateur inscrit.
USER_PERMISSIONS: list[str] = [
    "plugin:list",
    "plugin:read",
    "submissions:list",
    "submissions:read",
    "submissions:create",
    "submissions:write",
    "rating:create",
    "user:read",
]

# Propriétaire d'un tenant — gestion de SON tenant, pas de privilèges plateforme.
TENANT_ADMIN_PERMISSIONS: list[str] = [
    "tenants:read",
    "tenants:write",
    "invites:read",
    "invites:write",
    "audit:read",
    "rbac:read",
    "user:read",
    "license:read",
]

# ── Fonctions seed ────────────────────────────────────────────────────────────


async def seed_permissions(session: AsyncSession) -> dict[str, Permission]:
    """
    Synchronise le catalogue avec PERMISSIONS.
    Crée les nouvelles entrées ET met à jour description/group/tenant_grantable
    sur les existantes. Idempotent.
    """
    repo = PermissionRepository(session)
    result: dict[str, Permission] = {}
    for pdef in PERMISSIONS:
        existing = await repo.get_by_name(pdef.name)
        if existing is None:
            perm = Permission(
                name=pdef.name,
                description=pdef.description,
                group=pdef.group,
                tenant_grantable=pdef.tenant_grantable,
                active=True,
            )
            await repo.save(perm)
            result[pdef.name] = perm
            logger.debug("Permission créée : %s", pdef.name)
        else:
            changed = False
            if existing.description != pdef.description:
                existing.description = pdef.description
                changed = True
            if existing.group != pdef.group:
                existing.group = pdef.group
                changed = True
            if existing.tenant_grantable != pdef.tenant_grantable:
                existing.tenant_grantable = pdef.tenant_grantable
                changed = True
            if not existing.active:
                existing.active = True
                changed = True
            if changed:
                await repo.save(existing)
                logger.debug("Permission mise à jour : %s", pdef.name)
            result[pdef.name] = existing
    return result


def _sync_role_permissions(
    role: Role,
    target_names: set[str],
    catalogue: dict[str, Permission],
) -> int:
    """
    Synchronise les permissions d'un rôle avec target_names (déclaratif).
    Ajoute les manquantes, retire celles qui ne sont plus dans la liste.
    Retourne le nombre de modifications effectuées.
    """
    current: dict[str, Permission] = {p.name: p for p in role.permissions}
    delta = 0
    for name in target_names:
        if name not in current:
            perm = catalogue.get(name)
            if perm is not None:
                role.permissions.append(perm)
                delta += 1
    for name, perm in list(current.items()):
        if name not in target_names:
            role.permissions.remove(perm)
            delta += 1
    return delta


async def seed_default_tenant(session: AsyncSession, cfg: dict) -> Tenant:
    repo = TenantRepository(session)
    tenant = await repo.get_by_slug(cfg["ADMIN_TENANT_SLUG"])
    if tenant is None:
        tenant = Tenant(name=cfg["ADMIN_TENANT_NAME"], slug=cfg["ADMIN_TENANT_SLUG"])
        await repo.save(tenant)
        logger.info("Tenant '%s' créé", cfg["ADMIN_TENANT_SLUG"])
    return tenant


async def seed_admin_role(
    session: AsyncSession,
    tenant_id: str | None,
    permissions: dict[str, Permission],
    cfg: dict,
) -> Role:
    role_repo = RoleRepository(session)
    existing_roles = await role_repo.list_for_tenant(None)
    admin_role = next(
        (r for r in existing_roles if r.name == cfg["ADMIN_ROLE_NAME"]), None
    )

    if admin_role is None:
        admin_role = Role(
            name=cfg["ADMIN_ROLE_NAME"],
            tenant_id=None,
            description="Accès administrateur complet à toutes les ressources",
        )
        await role_repo.save(admin_role)
        logger.info("Rôle admin créé")

    admin_role = await role_repo.get_with_permissions(admin_role.id)
    delta = _sync_role_permissions(admin_role, set(permissions.keys()), permissions)
    if delta:
        logger.info("Rôle admin : %d permission(s) synchronisée(s)", delta)
    await session.flush()
    return admin_role


async def seed_user_role(
    session: AsyncSession,
    permissions: dict[str, Permission],
    cfg: dict,
) -> Role:
    role_repo = RoleRepository(session)
    existing_roles = await role_repo.list_for_tenant(None)
    user_role = next(
        (r for r in existing_roles if r.name == cfg["USER_ROLE_NAME"]), None
    )

    if user_role is None:
        user_role = Role(
            name=cfg["USER_ROLE_NAME"],
            tenant_id=None,
            description="Accès standard pour les utilisateurs inscrits",
        )
        await role_repo.save(user_role)
        logger.info("Rôle user créé")

    user_role = await role_repo.get_with_permissions(user_role.id)
    delta = _sync_role_permissions(user_role, set(USER_PERMISSIONS), permissions)
    if delta:
        logger.info("Rôle user : %d permission(s) synchronisée(s)", delta)
    await session.flush()
    return user_role


async def seed_tenant_admin_role(
    session: AsyncSession,
    permissions: dict[str, Permission],
    role_name: str = "tenant_admin",
) -> Role:
    """
    Rôle global attribué au propriétaire d'un tenant : gère son tenant sans
    aucun privilège plateforme (pas de admin:*). Distinct du rôle 'admin'.
    """
    role_repo = RoleRepository(session)
    existing_roles = await role_repo.list_for_tenant(None)
    role = next((r for r in existing_roles if r.name == role_name), None)

    if role is None:
        role = Role(
            name=role_name,
            tenant_id=None,
            description="Propriétaire d'un tenant — gestion limitée à son tenant",
        )
        await role_repo.save(role)
        logger.info("Rôle '%s' créé", role_name)

    role = await role_repo.get_with_permissions(role.id)
    delta = _sync_role_permissions(role, set(TENANT_ADMIN_PERMISSIONS), permissions)
    if delta:
        logger.info("Rôle tenant_admin : %d permission(s) synchronisée(s)", delta)
    await session.flush()
    return role


async def seed_admin_user(
    session: AsyncSession,
    tenant: Tenant,
    admin_role: Role,
    cfg: dict,
) -> User:
    user_repo = UserRepository(session)
    member_repo = TenantMemberRepository(session)

    user = await user_repo.get_by_email(cfg["ADMIN_EMAIL"])
    if user is None:
        hashed = get_pwd_context().hash(cfg["ADMIN_PASSWORD"])
        user = User(email=cfg["ADMIN_EMAIL"], hashed_password=hashed, is_active=True)
        await user_repo.save(user)
        logger.info("Utilisateur admin créé : %s", cfg["ADMIN_EMAIL"])

    membership = await member_repo.get_membership(user.id, tenant.id)
    if membership is None:
        membership = TenantMember(
            user_id=user.id,
            tenant_id=tenant.id,
            role_id=admin_role.id,
            is_owner=True,
        )
        await member_repo.save(membership)
        logger.info("Membership admin créé pour tenant '%s'", tenant.slug)
    elif membership.role_id != admin_role.id or not membership.is_owner:
        membership.role_id = admin_role.id
        membership.is_owner = True
        await session.flush()

    return user


async def get_default_user_role(db: Any, user_role_name: str = "user") -> Role | None:
    """Retourne le rôle user global — utilisé lors de l'inscription OAuth."""
    async with db.session() as session:
        role_repo = RoleRepository(session)
        roles = await role_repo.list_for_tenant(None)
        return next((r for r in roles if r.name == user_role_name), None)


async def run_seed(db: Any, cfg: dict) -> None:
    """
    Point d'entrée principal — appelé depuis Plugin.on_load.
    cfg est construit par _build_seed_cfg() dans main.py (plugin.yaml > env vars).
    """
    async with db.session() as session:
        try:
            permissions = await seed_permissions(session)
            tenant = await seed_default_tenant(session, cfg)
            admin_role = await seed_admin_role(session, tenant.id, permissions, cfg)
            await seed_user_role(session, permissions, cfg)
            await seed_tenant_admin_role(session, permissions)
            await seed_admin_user(session, tenant, admin_role, cfg)
            await session.commit()
            logger.info(
                "Seed xauth terminé — %d permissions, rôles admin+user créés",
                len(permissions),
            )
        except Exception:
            await session.rollback()
            logger.exception("Erreur lors du seed xauth")
            raise

    # Cleanup des invitations expirées au démarrage
    try:
        async with db.session() as session:
            from ..repositories.invite import InviteRepository

            repo = InviteRepository(session)
            count = await repo.deactivate_expired()
            if count:
                logger.info(
                    "Cleanup : %d invitation(s) expirée(s) désactivée(s)", count
                )
            await session.commit()
    except Exception:
        logger.warning("Cleanup invitations échoué (non bloquant)", exc_info=True)
