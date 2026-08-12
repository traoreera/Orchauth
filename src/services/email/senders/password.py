from __future__ import annotations

from ....utils.deeplink import wrap_bridge
from ..base import EmailTransport


class PasswordEmailSender(EmailTransport):
    """Emails liés à la gestion des mots de passe."""

    async def reset(
        self,
        to: str,
        username: str,
        reset_token: str,
        expires_minutes: int = 30,
    ) -> bool:
        # Auparavant un lien direct vers l'endpoint API POST-only (auth
        # Constat 9) — désormais un deep-link erp://password-reset emballé
        # dans la page de rebond https, cohérent avec invitation/oauth.
        reset_url = wrap_bridge(self.base_url, f"erp://password-reset?token={reset_token}")
        return await self.send(
            to=to,
            subject="Réinitialisation de votre mot de passe",
            template="password_reset",
            context={
                "username": username,
                "reset_url": reset_url,
                "expires_in_minutes": expires_minutes,
            },
        )

    async def changed(self, to: str, username: str) -> bool:
        return await self.send(
            to=to,
            subject="Votre mot de passe a été modifié",
            template="password_changed",
            context={"username": username},
        )
