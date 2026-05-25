from __future__ import annotations

import logging
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

# ── Permissions à créer au démarrage ─────────────────────────────────────────

PERMISSIONS: list[tuple[str, str]] = [
    # Plugins
    ("plugin:list",    "Lister les plugins"),
    ("plugin:read",    "Lire un plugin"),
    ("plugin:create",  "Publier un plugin"),
    ("plugin:update",  "Modifier un plugin"),
    ("plugin:delete",  "Supprimer un plugin"),
    ("plugin:approve", "Approuver un plugin"),
    ("plugin:reject",  "Rejeter un plugin"),
    ("plugin:feature", "Mettre en avant un plugin"),
    # Soumissions
    ("submissions:list",   "Lister les soumissions"),
    ("submissions:read",   "Lire une soumission"),
    ("submissions:create", "Créer une soumission"),
    ("submissions:review", "Réviser une soumission"),
    ("submissions:approve","Approuver une soumission"),
    ("submissions:reject", "Rejeter une soumission"),
    ("submissions:delete", "Supprimer une soumission"),
    ("submissions:write",  "Poster un nouveau plugin"),
    # Évaluations
    ("rating:create", "Créer une évaluation"),
    ("rating:delete", "Supprimer une évaluation"),
    # Utilisateurs
    ("user:list",   "Lister les utilisateurs"),
    ("user:read",   "Lire un utilisateur"),
    ("user:update", "Modifier un utilisateur"),
    ("user:delete", "Supprimer un utilisateur"),
    ("user:ban",    "Bannir un utilisateur"),
    # Tenants
    ("tenant:list",   "Lister les tenants"),
    ("tenant:read",   "Lire un tenant"),
    ("tenant:create", "Créer un tenant"),
    ("tenant:update", "Modifier un tenant"),
    ("tenant:delete", "Supprimer un tenant"),
    ("tenants:read",  "Lire les tenants (routes API)"),
    ("tenants:write", "Modifier les tenants (routes API)"),
    ("tenants:delete","Supprimer les tenants (routes API)"),
    # RBAC
    ("role:list",        "Lister les rôles"),
    ("role:create",      "Créer un rôle"),
    ("role:update",      "Modifier un rôle"),
    ("role:delete",      "Supprimer un rôle"),
    ("permission:list",  "Lister les permissions"),
    ("permission:assign","Assigner une permission"),
    ("rbac:read",  "Lire les rôles et permissions (routes API)"),
    ("rbac:write", "Modifier les rôles et permissions (routes API)"),
    # Audit
    ("audit:read", "Lire les logs d'audit"),
    # Invitations
    ("invite:create", "Créer une invitation"),
    ("invite:revoke", "Révoquer une invitation"),
    # Admin global
    ("admin:*", "Accès administrateur complet"),
    # xpulse
    ("xpulse:publish",   "Publier un message ciblé via xpulse"),
    ("xpulse:broadcast", "Broadcaster un message à tous les users via xpulse"),
]

# Permissions accordées à tout utilisateur inscrit
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

# ── Fonctions seed ────────────────────────────────────────────────────────────

async def seed_permissions(session: AsyncSession) -> dict[str, Permission]:
    repo = PermissionRepository(session)
    result: dict[str, Permission] = {}
    for name, desc in PERMISSIONS:
        existing = await repo.get_by_name(name)
        if existing is None:
            perm = Permission(name=name, description=desc)
            await repo.save(perm)
            result[name] = perm
            logger.debug("Permission créée : %s", name)
        else:
            result[name] = existing
    return result


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
    admin_role = next((r for r in existing_roles if r.name == cfg["ADMIN_ROLE_NAME"]), None)

    if admin_role is None:
        admin_role = Role(
            name=cfg["ADMIN_ROLE_NAME"],
            tenant_id=None,
            description="Accès administrateur complet à toutes les ressources",
        )
        await role_repo.save(admin_role)
        logger.info("Rôle admin créé")

    admin_role = await role_repo.get_with_permissions(admin_role.id)
    existing_perm_names = {p.name for p in admin_role.permissions}
    for perm in permissions.values():
        if perm.name not in existing_perm_names:
            admin_role.permissions.append(perm)

    await session.flush()
    return admin_role


async def seed_user_role(
    session: AsyncSession,
    permissions: dict[str, Permission],
    cfg: dict,
) -> Role:
    role_repo = RoleRepository(session)
    existing_roles = await role_repo.list_for_tenant(None)
    user_role = next((r for r in existing_roles if r.name == cfg["USER_ROLE_NAME"]), None)

    if user_role is None:
        user_role = Role(
            name=cfg["USER_ROLE_NAME"],
            tenant_id=None,
            description="Accès standard pour les utilisateurs inscrits",
        )
        await role_repo.save(user_role)
        logger.info("Rôle user créé")

    user_role_loaded = await role_repo.get_with_permissions(user_role.id)
    assert user_role_loaded is not None
    existing_perm_names = {p.name for p in user_role_loaded.permissions}
    for perm_name in USER_PERMISSIONS:
        perm = permissions.get(perm_name)
        if perm and perm.name not in existing_perm_names:
            user_role_loaded.permissions.append(perm)

    await session.flush()
    return user_role_loaded


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
            tenant      = await seed_default_tenant(session, cfg)
            admin_role  = await seed_admin_role(session, tenant.id, permissions, cfg)
            await seed_user_role(session, permissions, cfg)
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
                logger.info("Cleanup : %d invitation(s) expirée(s) désactivée(s)", count)
            await session.commit()
    except Exception:
        logger.warning("Cleanup invitations échoué (non bloquant)", exc_info=True)
