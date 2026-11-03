from __future__ import annotations

from urllib.parse import urlencode

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
        # Lien WEB vers la page du Desk (`#/reset?token=…`), jamais un deep-link `erp://` : le destinataire ouvre son navigateur.
        reset_url = f"{self.desk_url}#/reset?{urlencode({'token': reset_token})}"
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
