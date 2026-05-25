from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..providers.base import OAuthProvider
from ..services.oauth import OAuthService
from ..services.token import TokenService


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

    def _extract_ip(request: Request) -> str:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    @router.get("/providers")
    async def list_providers() -> Any:
        """Liste les providers OAuth configurés et actifs."""
        return {"providers": list(providers.keys())}

    @router.get("/{provider}/authorize")
    async def authorize(
        provider: str,
        tenant_id: str | None = None,
        redirect: str | None = None,
    ) -> Any:
        """
        Retourne l'URL d'autorisation du provider.
        Le client redirige l'utilisateur vers cette URL.
        """
        async with db.session() as session:
            svc = _svc(session)
            try:
                url = await svc.get_auth_url(
                    provider, tenant_id=tenant_id, post_login_redirect=redirect
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
        retourne les tokens xauth.
        """
        ip = _extract_ip(request)
        async with db.session() as session:
            svc = _svc(session)
            try:
                result = await svc.handle_callback(provider, code, state, ip_address=ip)
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            except Exception as exc:
                raise HTTPException(status_code=502, detail=f"Erreur provider : {exc}")

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
