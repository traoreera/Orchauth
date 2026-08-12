from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse

from ..utils.deeplink import ALLOWED_BRIDGE_SCHEMES

_TITLES = {
    "oauth-callback": "Connexion réussie",
    "oauth-link": "Compte lié",
    "invite": "Invitation acceptée",
    "password-reset": "Réinitialisation du mot de passe",
    "login": "Retour à l'application",
}

_MESSAGES = {
    "oauth-callback": "Vous êtes connecté.",
    "oauth-link": "Le fournisseur a été lié à votre compte.",
    "invite": "Votre invitation a été acceptée.",
    "password-reset": "Ouvrez {app_name} pour définir votre nouveau mot de passe.",
    "login": "Ouvrez {app_name} pour vous connecter.",
}


def bridge_router(app_name: str) -> APIRouter:
    router = APIRouter(tags=["bridge"])

    @router.get("/redirect", response_class=HTMLResponse)
    async def redirect_bridge(target: str, title: str | None = None, message: str | None = None) -> Any:
        """
        Page de rebond https partagée, réutilisée par l'invitation, le reset de
        mot de passe et le retour de connexion : reçoit un deep-link non http(s)
        et relaie le navigateur dessus, avec un message adapté et un bouton de
        secours si l'application n'est pas installée.
        """
        # Import différé pour éviter un cycle d'import au chargement du module
        # (services.email.__init__ importe les senders, qui importent
        # ..utils.deeplink — jamais routes.bridge, mais on garde ce module
        # sans dépendance descendante vers services par prudence).
        from ..services.email.base import _render

        scheme = urlsplit(target).scheme
        if scheme not in ALLOWED_BRIDGE_SCHEMES:
            raise HTTPException(
                status_code=400,
                detail=f"Schéma de retour non autorisé : '{scheme or target}'.",
            )

        host = urlsplit(target).netloc or urlsplit(target).path.lstrip("/")
        resolved_title = title or _TITLES.get(host, f"Retour vers {app_name}")
        resolved_message = message or _MESSAGES.get(
            host, "Retour vers {app_name}..."
        ).format(app_name=app_name)

        html = _render(
            "redirect_bridge",
            {
                "app_name": app_name,
                "title": resolved_title,
                "message": resolved_message,
                "deep_link": target,
                "status": "success",
                "badge_label": "Redirection",
            },
        )
        return HTMLResponse(content=html)

    return router
