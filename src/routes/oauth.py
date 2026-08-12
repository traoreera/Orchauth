from __future__ import annotations

import base64
import json
import urllib.parse
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_auth_backend, get_current_user
from xcore.sdk import get_logger

from ..providers.base import OAuthProvider
from ..services.oauth import OAuthService
from ..services.token import TokenService
from ..utils.http import get_client_ip

logger = get_logger("xauth.routes.oauth")


class OAuthLinkRequest(BaseModel):
    code: str
    state: str


_DEFAULT_CALLBACK_REDIRECT = "erp://oauth-callback"
_DEFAULT_LINK_REDIRECT = "erp://oauth-link"


def _append_params(base: str, params: dict[str, str]) -> str:
    """Ajoute `params` à `base`, qu'il s'agisse d'un deep-link `erp://...`
    sans query string ou d'une URL web fournie par le client qui peut déjà
    en porter une (ex. `https://app.com/callback?tenant=x`)."""
    sep = "&" if "?" in base else "?"
    return f"{base}{sep}{urllib.parse.urlencode(params)}"


def oauth_router(
    db: Any,
    cache: Any,
    token_service: TokenService,
    providers: dict[str, OAuthProvider],
    token_cipher: Any = None,
    web_redirect_origins: frozenset[str] = frozenset(),
) -> APIRouter:
    router = APIRouter(prefix="/oauth", tags=["oauth"])

    def _svc(session) -> OAuthService:
        return OAuthService(
            session, token_service, cache, providers,
            token_cipher=token_cipher, web_origins=web_redirect_origins,
        )

    @router.get("/providers")
    async def list_providers() -> Any:
        """Liste les providers OAuth configurés et actifs."""
        return {"providers": list(providers.keys())}

    @router.get("/{provider}/authorize")
    async def authorize(
        provider: str,
        request: Request,
        tenant_id: str | None = None,
        redirect: str | None = None,
        link_user_id: str | None = None,
        app_state: str | None = None,
    ) -> Any:
        """
        Retourne l'URL d'autorisation du provider.
        Le client redirige l'utilisateur vers cette URL.

        `redirect` : cible de la redirection finale du callback — un
        deep-link desktop (`erp://oauth-callback`, valeur implicite si omis)
        ou une URL web `https://...` dont l'origine est déclarée dans
        OAUTH_WEB_REDIRECT_ORIGINS. Auparavant ignoré (le callback
        redirigeait TOUJOURS vers `erp://`, quel que soit ce paramètre) :
        un client web n'avait alors aucun moyen de récupérer sa propre
        session après connexion. Validé par `OAuthService.get_auth_url` —
        401/400 immédiat si l'origine n'est pas autorisée, plutôt qu'une
        redirection silencieusement perdue au retour du provider.

        `app_state` : nonce généré par le client avant d'ouvrir le
        navigateur. Échoué tel quel dans la redirection finale, pour que le
        client puisse vérifier que ce retour correspond bien à une
        tentative de connexion qu'il a lui-même initiée.
        """
        # `link_user_id` déclenche le mode liaison (le callback attachera le
        # compte provider à ce user_id, sans jamais recréer de session).
        # Auparavant la valeur du query param était prise telle quelle, sans
        # aucune vérification — n'importe quel appelant pouvait lier SA
        # propre identité OAuth au user_id de N'IMPORTE QUI D'AUTRE (prise
        # de compte totale, aucune preuve de possession requise). On ignore
        # désormais la valeur fournie et on ne fait confiance qu'à l'identité
        # du token Bearer déjà vérifié — la même protection que la route
        # authentifiée POST /{provider}/link, appliquée ici aussi puisque le
        # frontend desktop utilise réellement ce chemin GET pour lier un
        # compte (erp/src/shell/settings/connections.tsx).
        resolved_link_user_id: str | None = None
        if link_user_id:
            backend = get_auth_backend()
            if backend is None:
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Auth backend non disponible.",
                )
            token = await backend.extract_token(request)
            payload = await backend.decode_token(token) if token else None
            if not payload:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentification requise pour lier un compte.",
                )
            resolved_link_user_id = payload.get("sub")

        async with db.session() as session:
            svc = _svc(session)
            try:
                url = await svc.get_auth_url(
                    provider,
                    tenant_id=tenant_id,
                    post_login_redirect=redirect,
                    link_user_id=resolved_link_user_id,
                    app_state=app_state,
                )
                return {"auth_url": url, "provider": provider}
            except ValueError as exc:
                raise HTTPException(status_code=400, detail="Provider Error")

    @router.get("/{provider}/callback")
    async def callback(
        provider: str,
        request: Request,
        code: str,
        state: str,
    ) -> Any:
        """
        Point d'entrée retour provider. Échange le code, crée/retrouve le user,
        redirige vers la cible négociée à l'étape /authorize — un deep-link
        desktop (`erp://oauth-callback`, par défaut) ou l'origine web du
        client si elle a été validée (voir `redirect` sur /authorize).
        Auparavant, cette redirection était TOUJOURS `erp://...` en dur, quel
        que soit le client d'origine — un utilisateur web n'avait alors
        aucun moyen de récupérer sa session après connexion.
        """
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = _svc(session)
            try:
                result = await svc.handle_callback(provider, code, state, ip_address=ip)
                await session.commit()
            except Exception as exc:
                # Détail complet en log serveur — jamais renvoyé au client, qui ne
                # reçoit qu'un message générique + code stable pour éviter toute
                # fuite d'information via l'URL de redirection. La cible n'est pas
                # récupérable ici (l'échec peut survenir avant la résolution du
                # state) : repli sur le deep-link desktop, comme avant ce correctif.
                logger.exception(
                    "OAuth callback failed for provider=%s: %s", provider, exc
                )
                error = urllib.parse.quote("oauth_callback_failed", safe="")
                return RedirectResponse(
                    _append_params(_DEFAULT_CALLBACK_REDIRECT, {"error": error}), status_code=302
                )

        # Mode liaison → <redirect ou erp://oauth-link>?success=true&...
        if result.get("is_link"):
            link_params = {
                "success": "true",
                "provider": result.get("provider", ""),
                "email": result.get("provider_email", "") or "",
            }
            if app_state := result.get("app_state"):
                link_params["state"] = app_state
            base = result.get("post_login_redirect") or _DEFAULT_LINK_REDIRECT
            return RedirectResponse(_append_params(base, link_params), status_code=302)

        # Mode login → <redirect ou erp://oauth-callback>?...
        params: dict[str, str] = {
            "access_token": result.get("access_token", "") or "",
            "refresh_token": result.get("refresh_token", "") or "",
            "user_id": result.get("user_id", "") or "",
        }
        # Compte protégé par MFA : aucun token utilisable n'a été émis, seul
        # un challenge — le client doit le compléter comme pour un login par
        # mot de passe, jamais adopter de session directement.
        if result.get("mfa_required"):
            params["mfa_required"] = "true"
            params["mfa_token"] = result.get("mfa_token", "") or ""
            if tenant_id := result.get("tenant_id"):
                params["tenant_id"] = tenant_id
        if result.get("onboarding_required"):
            params["onboarding"] = "true"
        if tenants := result.get("tenants"):
            params["tenants"] = base64.b64encode(json.dumps(tenants).encode()).decode()
        # Échoué tel quel — voir OAuthService.get_auth_url : permet au client
        # de vérifier que ce retour correspond à une tentative qu'il a lui
        # même initiée, plutôt qu'un callback forgé et invoqué directement
        # par un tiers hors de tout flow OAuth réel.
        if app_state := result.get("app_state"):
            params["app_state"] = app_state

        base = result.get("post_login_redirect") or _DEFAULT_CALLBACK_REDIRECT
        return RedirectResponse(_append_params(base, params), status_code=302)

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
                raise HTTPException(status_code=400, detail="Unlink Error")

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
