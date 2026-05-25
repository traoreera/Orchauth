from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from xcore.kernel.api import (
    AuthPayload,
    get_current_user,
    register_auth_backend,
    unregister_auth_backend,
)
from xcore.sdk import AutoDispatchMixin, TrustedBase

from .backend import XAuthBackend
from .ipc import IPCCommands
from .models import Base
from .providers import (
    DiscordProvider,
    GitHubProvider,
    GoogleProvider,
    MicrosoftProvider,
)
from .providers.base import OAuthProvider
from .routes import (
    audit_router,
    invites_router,
    mfa_router,
    oauth_router,
    password_router,
    rbac_router,
    tenants_router,
)
from .routes.admin import admin_router
from .routes.sessions import sessions_router
from .schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    SetupCreateRequest,
    SetupJoinRequest,
    TokenResponse,
    UserResponse,
)
from .services.auth import AuthService
from .services.email import AuthEmailService
from .services.events import XAuthEvents
from .services.seed import run_seed
from .services.token import TokenService


class Plugin(IPCCommands, AutoDispatchMixin, TrustedBase):
    """
    XAuth Plugin — enterprise auth multi-tenant avec RBAC, audit log, invitations.
    Enregistre un AuthBackend global au boot : tous les autres plugins peuvent utiliser
    require_permission() / get_current_user() de xcore.sdk sans dépendre de xauth.
    """

    async def _initialize_tables(self, db) -> None:
        import logging as _log

        from xcore.services.database.migrations import MigrationRunner

        _logger = _log.getLogger("hub.xauth")
        async with db.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _logger.info("[xauth] Tables créées / vérifiées")
        _migrations_dir = Path(__file__).parent.parent / "migrations"
        runner = MigrationRunner(
            db_url=str(db.engine.url), migrations_dir=_migrations_dir
        )
        try:
            await runner.init(autogenerate=False, message="first_initialisation")
            await runner.upgrade()
        except Exception as exc:
            _logger.warning("[xauth] Migration upgrade ignorée : %s", exc)

    async def on_load(self) -> None:
        self.app = APIRouter()

        env = self.ctx.env  # type: ignore  — vars d'env résolues (secrets)
        cfg = self.ctx.config  # type: ignore  — sections extra de plugin.yaml

        db = self.get_service("db")
        cache = self.get_service("cache")

        await self._initialize_tables(db)

        self._db = db
        self._cache = cache

        # ── Résolution config : plugin.yaml > env vars ──────────────────────
        app_cfg = cfg.get("app", {})
        jwt_cfg = cfg.get("jwt", {})

        app_name = env.get("APP_NAME") or app_cfg.get("name", "XAuth")
        app_base_url = env.get("APP_BASE_URL") or app_cfg.get(
            "base_url", "http://localhost:8000"
        )

        private_key = env.get("JWT_PRIVATE_KEY_PATH") or jwt_cfg.get(
            "private_key_path", "conf/private.pem"
        )
        public_key = env.get("JWT_PUBLIC_KEY_PATH") or jwt_cfg.get(
            "public_key_path", "conf/public.pem"
        )
        access_exp = int(
            env.get("JWT_ACCESS_EXPIRE_MINUTES")
            or jwt_cfg.get("access_expire_minutes", 15)
        )
        refresh_exp = int(
            env.get("JWT_REFRESH_EXPIRE_DAYS") or jwt_cfg.get("refresh_expire_days", 7)
        )

        # ── Services ────────────────────────────────────────────────────────
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

        oauth_providers = _build_oauth_providers(env, app_base_url)

        seed_cfg = cfg.get("seed", {})
        user_role_name = env.get("USER_ROLE_NAME") or seed_cfg.get(
            "user_role_name", "user"
        )
        admin_role_name = env.get("ADMIN_ROLE_NAME") or seed_cfg.get(
            "admin_role_name", "admin"
        )

        # ── Routes ──────────────────────────────────────────────────────────
        self.app.include_router(
            _auth_router_with_db(
                db,
                self._token_service,
                self._email_service,
                self._events,
                cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
        )
        self.app.include_router(tenants_router(db, self._events))
        self.app.include_router(rbac_router(db, cache=cache))
        self.app.include_router(mfa_router(db, self._token_service))
        self.app.include_router(invites_router(db, self._email_service, self._events))
        self.app.include_router(audit_router(db))
        self.app.include_router(
            oauth_router(db, cache, self._token_service, oauth_providers)
        )
        self.app.include_router(
            password_router(db, cache, self._email_service, self._events)
        )
        self.app.include_router(sessions_router(db, self._token_service, cache=cache))
        self.app.include_router(
            admin_router(db, cache=cache, token_service=self._token_service)
        )

        # ── Seed ────────────────────────────────────────────────────────────
        from .services.seed import run_seed

        await run_seed(db, cfg=_build_seed_cfg(cfg.get("seed", {}), env))

    async def on_unload(self) -> None:
        unregister_auth_backend()

    def get_router(self) -> APIRouter | None:
        return self.app


def _build_seed_cfg(seed_yaml: dict, env: dict) -> dict:
    """
    Construit le dict de config seed.
    Priorité : env vars > section seed: de plugin.yaml.
    Lève RuntimeError si une clé requise est absente des deux sources.
    """
    fields = {
        "ADMIN_EMAIL": "admin_email",
        "ADMIN_PASSWORD": "admin_password",
        "ADMIN_TENANT_SLUG": "admin_tenant_slug",
        "ADMIN_TENANT_NAME": "admin_tenant_name",
        "ADMIN_ROLE_NAME": "admin_role_name",
        "USER_ROLE_NAME": "user_role_name",
    }
    result: dict = {}
    missing: list[str] = []
    for env_key, yaml_key in fields.items():
        value = env.get(env_key) or seed_yaml.get(yaml_key)
        if not value:
            missing.append(f"seed.{yaml_key}")
        else:
            result[env_key] = value
    if missing:
        raise RuntimeError(
            "[xauth] Configuration seed incomplète — champs manquants dans plugin.yaml : "
            + ", ".join(missing)
        )
    return result


def _auth_router_with_db(
    db,
    token_service: TokenService,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
    cache=None,
    user_role_name: str = "user",
    admin_role_name: str = "admin",
) -> APIRouter:
    router = APIRouter(tags=["auth"])

    def _extract_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @router.post(
        "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
    )
    async def register(body: RegisterRequest):
        async with db.session() as session:
            svc = AuthService(
                session,
                token_service,
                events,
                cache=cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
            try:
                user = await svc.register(
                    email=body.email,
                    password=body.password,
                )
                await session.commit()
                await session.refresh(user)
                email_service.auth.queue_template(
                    to=user.email,
                    subject=f"Bienvenue sur {email_service.auth.app_name}",
                    template="welcome",
                    context={
                        "username": user.email,
                        "login_url": f"{email_service.auth.base_url}/login",
                    },
                )
                return user
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.post("/login", response_model=TokenResponse)
    async def login(body: LoginRequest, request: Request):
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = AuthService(
                session,
                token_service,
                events,
                cache=cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
            try:
                result = await svc.login(
                    email=body.email,
                    password=body.password,
                    tenant_id=body.tenant_id,
                    ip_address=ip,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(body: RefreshRequest, request: Request):
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = AuthService(
                session,
                token_service,
                events,
                cache=cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
            try:
                result = await svc.refresh(
                    refresh_token=body.refresh_token, ip_address=ip
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(body: LogoutRequest):
        async with db.session() as session:
            svc = AuthService(
                session,
                token_service,
                events,
                cache=cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
            await svc.logout(body.refresh_token)
            await session.commit()

    @router.post("/setup/create", response_model=TokenResponse)
    async def setup_create(body: SetupCreateRequest, request: Request):
        """
        Crée un nouveau tenant et y rattache l'utilisateur comme owner.
        À appeler après un login qui retourne onboarding_required=true.
        """
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = AuthService(
                session,
                token_service,
                events,
                cache=cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
            try:
                result = await svc.setup_create_tenant(
                    refresh_token=body.refresh_token,
                    name=body.name,
                    slug=body.slug,
                    ip_address=ip,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.post("/setup/join", response_model=TokenResponse)
    async def setup_join(body: SetupJoinRequest, request: Request):
        """
        Rejoint un tenant existant via un token d'invitation.
        À appeler après un login qui retourne onboarding_required=true.
        """
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = AuthService(
                session,
                token_service,
                events,
                cache=cache,
                user_role_name=user_role_name,
                admin_role_name=admin_role_name,
            )
            try:
                result = await svc.setup_join_tenant(
                    refresh_token=body.refresh_token,
                    invite_token=body.invite_token,
                    ip_address=ip,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/me", response_model=UserResponse)
    async def me(current_user: AuthPayload = Depends(get_current_user)):
        from .repositories.user import UserRepository  # évite l'import circulaire

        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get(current_user["sub"])
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")
            return user

    return router


def _build_oauth_providers(
    env: dict, base_url: str = "http://localhost:8000"
) -> dict[str, OAuthProvider]:
    """
    Construit le dict provider_name → instance à partir des vars d'env.
    Un provider est activé seulement si client_id et client_secret sont présents.
    """
    base_url = base_url.rstrip("/")
    providers: dict[str, OAuthProvider] = {}

    _registry = [
        (
            "google",
            GoogleProvider,
            "OAUTH_GOOGLE_CLIENT_ID",
            "OAUTH_GOOGLE_CLIENT_SECRET",
        ),
        (
            "github",
            GitHubProvider,
            "OAUTH_GITHUB_CLIENT_ID",
            "OAUTH_GITHUB_CLIENT_SECRET",
        ),
        (
            "discord",
            DiscordProvider,
            "OAUTH_DISCORD_CLIENT_ID",
            "OAUTH_DISCORD_CLIENT_SECRET",
        ),
        (
            "microsoft",
            MicrosoftProvider,
            "OAUTH_MICROSOFT_CLIENT_ID",
            "OAUTH_MICROSOFT_CLIENT_SECRET",
        ),
    ]

    for name, cls, id_key, secret_key in _registry:
        client_id = env.get(id_key, "")
        client_secret = env.get(secret_key, "")
        if client_id and client_secret:
            redirect_uri = f"{base_url}/xauth/oauth/{name}/callback"
            providers[name] = cls(client_id, client_secret, redirect_uri)

    return providers
