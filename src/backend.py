from __future__ import annotations

import contextlib
from typing import Any

from xcore.kernel.api.auth import AuthPayload
from xcore.sdk import get_logger

from .services.token import TokenService
from .repositories.user import UserRepository

logger = get_logger("xauth.backend")


class XAuthBackend:
    """
    Implémentation concrète du protocole AuthBackend de Xcore.

    Le protocole exige trois méthodes async :
        extract_token(request: RequestAdapter) -> str | None
        decode_token(token: str)              -> AuthPayload | None
        has_permission(payload, permission)   -> bool

    RequestAdapter expose : headers, cookies, query_params
    On cherche le token dans cet ordre :
        1. Authorization: Bearer <token>   (header standard)
        2. Cookie: access_token=<token>    (SPA same-site)
        3. ?access_token=<token>           (WebSocket / lien signé)
    """

    def __init__(self, token_service: TokenService, db: Any, cache: Any) -> None:
        self._token = token_service
        self._db = db
        self._cache = cache

    # ── Protocol AuthBackend ──────────────────────────────────────────────────

    async def extract_token(self, request: Any) -> str | None:
        # 1. Authorization header
        auth: str = request.headers.get("authorization") or request.headers.get("Authorization") or ""
        if auth.startswith("Bearer "):
            return auth[7:].strip() or None

        # 2. Cookie
        token = request.cookies.get("access_token")
        if token:
            return token

        # 3. Query param (WebSocket, liens signés)
        token = request.query_params.get("access_token")
        if token:
            logger.warning("Token transmitted via query param (insecure)")
        return token or None

    async def decode_token(self, token: str) -> AuthPayload | None:
        try:
            claims = self._token.verify_access_token(token)
        except ValueError:
            return None

        # Vérifier que le JTI n'est pas blacklisté (logout effectué)
        jti = claims.get("jti")
        if jti and self._cache:
            try:
                if await self._cache.get(f"xauth:jti_bl:{jti}"):
                    return None
            except Exception:
                logger.exception("JTI blacklist cache check failed, rejecting token")
                return None
        user_id: str = claims["sub"]
        tenant_id: str | None = claims.get("tenant_id")
        permissions: list[str] = []

        roles: list[str] = []
        with contextlib.suppress(Exception):
            async with self._db.session() as session:
                from .repositories.user import TenantMemberRepository
                if not tenant_id:
                    member_repo = TenantMemberRepository(session)
                    memberships = await member_repo.get_memberships_for_user(user_id)
                    if memberships:
                        tenant_id = memberships[0].tenant_id

                if tenant_id:
                    from .services.rbac import MemberRoleService, PermissionService

                    perm_svc = PermissionService(session, cache=self._cache)
                    permissions = await perm_svc.get_permissions_for_user(user_id, tenant_id)
                    member_svc = MemberRoleService(session, cache=self._cache)
                    roles = await member_svc.get_roles_for_user(user_id, tenant_id)
        async with self._db.session() as session:
            user_repo = UserRepository(session)
            user = await user_repo.get(user_id)
            if user is None:
                return None

        return AuthPayload(
            sub=user_id,
            roles=roles,
            permissions=permissions,
            user={
                "email": user.email,
                "tenant_id": tenant_id
            },
        )

    async def has_permission(self, payload: AuthPayload, permission: str) -> bool:
        return permission in set(payload.get("permissions", []))
