"""État du courrier sortant et envoi d'un message d'essai : pour l'écran Paramètres > Courrier du Desk.

L'extension `ext.email` (`extensions/xmailler`) est UNE pour tout l'hôte : son état et son essai concernent la plateforme, donc l'administrateur plateforme
(`admin:*`). Le mot de passe SMTP n'est jamais renvoyé, ni aucun secret : seulement ce qui permet de comprendre pourquoi un e-mail ne part pas.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, EmailStr
from xcore.kernel.api import AuthPayload, get_current_user

from ._scope import is_platform_admin


class MailTest(BaseModel):
    to: EmailStr


def mail_router(email_ext: Any) -> APIRouter:
    router = APIRouter(prefix="/mail", tags=["mail"])

    def admin_only(user: AuthPayload = Depends(get_current_user)) -> AuthPayload:
        if not is_platform_admin(user):
            raise HTTPException(status_code=403, detail="Réservé à l'administrateur de la plateforme")
        return user

    @router.get("/status")
    async def status(_: AuthPayload = Depends(admin_only)) -> dict:
        """Serveur SMTP désigné ou non, envoi simulé ou réel, compteurs ; `reachable` et `detail` disent si le serveur répond MAINTENANT."""
        info = dict(email_ext.status()) if hasattr(email_ext, "status") else {"name": "inconnu"}
        reachable, detail = None, None
        if hasattr(email_ext, "health_check"):
            try:
                reachable, detail = await email_ext.health_check()
            except Exception as e:  # noqa: BLE001 - un diagnostic ne doit jamais faire échouer la page
                reachable, detail = False, f"vérification impossible : {e}"
        info.pop("smtp_password", None)
        return {**info, "reachable": reachable, "detail": detail}

    @router.post("/test")
    async def test(body: MailTest, _: AuthPayload = Depends(admin_only)) -> dict:
        """Envoie un court message à `to` : `sent` dit si l'extension l'a accepté (simulé : journalisé seulement)."""
        sent = await email_ext.send(
            to=str(body.to),
            subject="Essai d'envoi",
            body="<p>Ceci est un message d'essai envoyé depuis les paramètres du Desk. S'il vous parvient, le courrier sortant fonctionne.</p>",
            is_html=True,
        )
        return {"sent": bool(sent), "simulated": bool(getattr(email_ext, "simulated", False))}

    return router
