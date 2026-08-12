from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter
from xcore.kernel.api import (
    register_auth_backend,
    unregister_auth_backend,
)
from xcore.sdk import AutoDispatchMixin, TrustedBase, get_logger

from .backend import XAuthBackend
from .ipc import IPCCommands
from .models import Base
from .providers._factory import build_oauth_providers
from .routes import (
    account_router,
    audit_router,
    auth_router,
    bridge_router,
    invites_router,
    mfa_router,
    notifications_router,
    oauth_router,
    password_router,
    rbac_router,
    sessions_router,
    tenants_router,
)
from .routes.admin import admin_router
from .services.email import AuthEmailService
from .services.events import XAuthEvents
from .services.rbac import PluginGrantService
from .services.seed import build_seed_cfg, run_seed
from .services.token import TokenService
from .services.token_crypto import OAuthTokenCipher

logger = get_logger('auth')


class Plugin(IPCCommands, AutoDispatchMixin, TrustedBase):

    async def _initialize_tables(self, db) -> None:
        from xcore.services.database.migrations import MigrationRunner
        async with db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("[xauth] Tables created / verified")
        _migrations_dir = Path(__file__).parent.parent / "migrations"
        runner = MigrationRunner(
            db_url=str(db.engine.url), migrations_dir=_migrations_dir
        )
        try:
            #await runner.init(autogenerate=True, message="first_initialisation")
            await runner.revision(autogenerate=True, message="first_initialisation")
            await runner.upgrade()
        except Exception as exc:
            logger.warning("[xauth] Migration upgrade skipped: %s", exc)

    async def on_load(self) -> None:
        self.app = APIRouter()

        env = self.ctx.env
        cfg = self.ctx.config

        db = self.get_service("db")
        cache = self.get_service("cache")
        await self._initialize_tables(db)

        self._db = db
        self._cache = cache

        app_cfg = cfg.get("app", {})
        jwt_cfg = cfg.get("jwt", {})

        app_name = env.get("APP_NAME") or app_cfg.get("name", "XAuth")
        app_base_url = app_cfg.get("base_url", "http://localhost:8000")

        private_key = env.get("JWT_PRIVATE_KEY_PATH") or jwt_cfg.get("private_key_path", "conf/private.pem")
        public_key = env.get("JWT_PUBLIC_KEY_PATH") or jwt_cfg.get("public_key_path", "conf/public.pem")
        access_exp = int(env.get("JWT_ACCESS_EXPIRE_MINUTES") or jwt_cfg.get("access_expire_minutes", 15))
        refresh_exp = int(env.get("JWT_REFRESH_EXPIRE_DAYS") or jwt_cfg.get("refresh_expire_days", 7))

        self._token_service = TokenService(
            private_key_path=private_key,
            public_key_path=public_key,
            access_expire_minutes=access_exp,
            refresh_expire_days=refresh_exp,
        )

        email_ext = self.get_service("ext.email")
        self._email_service = AuthEmailService(
            app_name=app_name,
            email_ext=email_ext,
            app_base_url=app_base_url,
        )

        register_auth_backend(
            XAuthBackend(token_service=self._token_service, db=db, cache=cache)
        )

        self._events = XAuthEvents(self.ctx.events)

        oauth_providers = build_oauth_providers(env, app_base_url)
        self._oauth_providers = oauth_providers

        # Chiffrement au repos des jetons Gmail/Calendar (voir
        # services/token_crypto.py) — sans clé configurée, le stockage de
        # jetons est simplement désactivé (login OAuth inchangé), jamais de
        # repli en clair.
        self._token_cipher = OAuthTokenCipher(env.get("OAUTH_TOKEN_KEY"))

        # Extension optionnelle (Gmail/Calendar au nom de l'utilisateur) —
        # absente dans un déploiement qui ne la configure pas, ne doit pas
        # empêcher le chargement du plugin auth (même garde que XPulses pour
        # ext.pubsub).
        self._google = None
        try:
            self._google = self.get_service("ext.google")
        except Exception as exc:
            logger.warning("[xauth] ext.google indisponible : %s", exc)

        # Origines web autorisées à recevoir la redirection finale du
        # callback OAuth (voir routes/oauth.py, utils/deeplink.py) — vide
        # par défaut : seul erp:// fonctionne tant qu'aucun frontend web
        # n'est déclaré ici. Ex. "https://app.orchestra.io,https://staging.orchestra.io".
        raw_web_origins = env.get("OAUTH_WEB_REDIRECT_ORIGINS") or ""
        web_redirect_origins = frozenset(
            origin.strip() for origin in raw_web_origins.split(",") if origin.strip()
        )

        seed_cfg = cfg.get("seed", {})
        user_role_name = env.get("USER_ROLE_NAME") or seed_cfg.get("user_role_name", "user")
        admin_role_name = env.get("ADMIN_ROLE_NAME") or seed_cfg.get("admin_role_name", "admin")
        self._admin_role_name = admin_role_name

        self.app.include_router(
            auth_router(
                db, self._token_service, self._email_service, self._events,
                cache, user_role_name=user_role_name, admin_role_name=admin_role_name,
            )
        )
        self.app.include_router(tenants_router(db, self._events))
        self.app.include_router(rbac_router(db, cache=cache))
        self.app.include_router(mfa_router(db, self._token_service, cache=cache))
        self.app.include_router(invites_router(db, self._email_service, self._events))
        self.app.include_router(audit_router(db))
        self.app.include_router(
            oauth_router(
                db, cache, self._token_service, oauth_providers,
                token_cipher=self._token_cipher, web_redirect_origins=web_redirect_origins,
            )
        )
        self.app.include_router(password_router(db, cache, self._email_service, self._events))
        self.app.include_router(sessions_router(db, self._token_service, cache=cache))
        self.app.include_router(
            account_router(db, self.call_plugin, event_bus=self.ctx.events, token_service=self._token_service)
        )
        self.app.include_router(notifications_router(db))
        self.app.include_router(admin_router(db, cache=cache, token_service=self._token_service))
        self.app.include_router(bridge_router(app_name))

        await run_seed(db, cfg=build_seed_cfg(cfg.get("seed", {}), env))
        self._register_rbac_listeners()

    def _register_rbac_listeners(self) -> None:
        events = self.ctx.events
        db = self._db
        admin_role_name = self._admin_role_name

        @events.on("rbac.declare")
        async def _on_rbac_declare(event):
            from .repositories.rbac import RoleRepository, PermissionRepository
            data = event.data or {}
            plugin = data.get("plugin")
            if not plugin:
                return
            async with db.session() as session:
                svc = PluginGrantService(session)
                await svc.reconcile_plugin_grants(plugin, data.get("grants", []))

                role_repo = RoleRepository(session)
                perm_repo = PermissionRepository(session)
                admin_role = await role_repo.get_by_name(admin_role_name)
                if admin_role:
                    plugin_perms = await perm_repo.list_by_plugin(plugin)
                    changed = False
                    for perm in plugin_perms:
                        if perm.active and perm not in admin_role.permissions:
                            admin_role.permissions.append(perm)
                            changed = True
                    if changed:
                        await session.flush()
                await session.commit()

        @events.on("plugin.*.unloaded")
        async def _on_plugin_unloaded(event):
            parts = (event.name or "").split(".")
            if len(parts) < 3:
                return
            plugin = parts[1]
            async with db.session() as session:
                svc = PluginGrantService(session)
                await svc.disable_plugin(plugin)
                await session.commit()

    async def on_unload(self) -> None:
        unregister_auth_backend()

    def get_router(self) -> APIRouter | None:
        return self.app
