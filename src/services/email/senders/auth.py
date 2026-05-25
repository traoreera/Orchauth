from __future__ import annotations

from ..base import EmailTransport


class AuthEmailSender(EmailTransport):
    """Emails liés à l'inscription et à la connexion."""

    async def welcome(self, to: str, username: str) -> bool:
        return await self.send(
            to=to,
            subject=f"Bienvenue sur {self.app_name}",
            template="welcome",
            context={"username": username},
        )

    async def oauth_linked(
        self,
        to: str,
        username: str,
        provider: str,
        provider_email: str,
    ) -> bool:
        return await self.send(
            to=to,
            subject=f"Compte {provider} lié à votre profil",
            template="oauth_linked",
            context={
                "username": username,
                "provider": provider.capitalize(),
                "provider_email": provider_email,
            },
        )
