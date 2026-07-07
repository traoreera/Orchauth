from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..providers.base import OAuthProvider
from ..services.oauth import OAuthService
from ..services.token import TokenService
from ..utils.http import get_client_ip


class OAuthLinkRequest(BaseModel):
    code: str
    state: str


def oauth_router(
    db: Any,
    cache: Any,
    token_service: TokenService,
    providers: dict[str, OAuthProvider],
) -> APIRouter:
    router = APIRouter(prefix="/oauth", tags=["oauth"])

    def _svc(session) -> OAuthService:
        return OAuthService(session, token_service, cache, providers)

    @router.get("/providers")
    async def list_providers() -> Any:
        """Liste les providers OAuth configurés et actifs."""
        return {"providers": list(providers.keys())}

    @router.get("/{provider}/authorize")
    async def authorize(
        provider: str,
        tenant_id: str | None = None,
        redirect: str | None = None,
        link_user_id: str | None = None,
    ) -> Any:
        """
        Retourne l'URL d'autorisation du provider.
        Le client redirige l'utilisateur vers cette URL.
        """
        async with db.session() as session:
            svc = _svc(session)
            try:
                url = await svc.get_auth_url(
                    provider,
                    tenant_id=tenant_id,
                    post_login_redirect=redirect,
                    link_user_id=link_user_id,
                )
                return {"auth_url": url, "provider": provider}
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/{provider}/callback")
    async def callback(
        provider: str,
        request: Request,
        code: str,
        state: str,
    ) -> Any:
        """
        Point d'entrée retour provider. Échange le code, crée/retrouve le user,
        redirige vers erp://oauth-callback?... (deep-link Tauri).
        """
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = _svc(session)
            try:
                result = await svc.handle_callback(provider, code, state, ip_address=ip)
                await session.commit()
            except (ValueError, Exception) as exc:
                error = urllib.parse.quote(str(exc), safe="")
                return RedirectResponse(f"erp://oauth-callback?error={error}", status_code=302)

        # Mode liaison → erp://oauth-link?success=true&...
        if result.get("is_link"):
            params = urllib.parse.urlencode({
                "success": "true",
                "provider": result.get("provider", ""),
                "email": result.get("provider_email", "") or "",
            })
            return RedirectResponse(f"erp://oauth-link?{params}", status_code=302)

        # Mode login → erp://oauth-callback?...
        params: dict[str, str] = {
            "access_token": result.get("access_token", "") or "",
            "refresh_token": result.get("refresh_token", "") or "",
            "user_id": result.get("user_id", "") or "",
        }
        if result.get("onboarding_required"):
            params["onboarding"] = "true"
        if tenants := result.get("tenants"):
            params["tenants"] = base64.b64encode(json.dumps(tenants).encode()).decode()

        redirect_url = "erp://oauth-callback?" + urllib.parse.urlencode(params)
        return RedirectResponse(redirect_url, status_code=302)

    @router.post("/{provider}/link")
    async def link_provider(
        provider: str,
        body: OAuthLinkRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """
        Lie un provider OAuth à un compte authentifié existant.
        Nécessite de compléter d'abord le flow authorize → callback du provider
        pour obtenir code + state.
        """
        async with db.session() as session:
            svc = _svc(session)
            try:
                account = await svc.link_provider(
                    user_id=user["sub"],
                    provider_name=provider,
                    code=body.code,
                    state=body.state,
                )
                await session.commit()
                return {
                    "success": True,
                    "provider": account.provider,
                    "provider_email": account.provider_email,
                }
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.delete("/{provider}/unlink", status_code=status.HTTP_204_NO_CONTENT)
    async def unlink_provider(
        provider: str,
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Délie un provider OAuth du compte authentifié."""
        async with db.session() as session:
            svc = _svc(session)
            try:
                await svc.unlink_provider(user_id=user["sub"], provider_name=provider)
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/me/accounts")
    async def list_linked_accounts(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Liste les comptes OAuth liés à l'utilisateur authentifié."""
        async with db.session() as session:
            from ..repositories.oauth import OAuthAccountRepository

            repo = OAuthAccountRepository(session)
            accounts = await repo.list_for_user(user["sub"])
            return [
                {
                    "provider": a.provider,
                    "provider_email": a.provider_email,
                    "provider_name": a.provider_name,
                    "provider_avatar": a.provider_avatar,
                    "linked_at": a.created_at.isoformat(),
                }
                for a in accounts
            ]

    return router
