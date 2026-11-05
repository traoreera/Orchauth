from __future__ import annotations

from urllib.parse import urlencode

from ..base import EmailTransport


class InviteEmailSender(EmailTransport):
    """Emails liés aux invitations."""

    async def send_invitation(
        self,
        to: str,
        invite_token: str,
        tenant_name: str,
        invited_by: str,
        expires_hours: int = 72,
        interface: str = "web",
    ) -> bool:
        # Lien WEB vers la page d'invitation du Desk (`#/invite?token=…`) : un invité sans application ouvre son
        # navigateur, et c'est le cas par défaut.
        #
        # `interface: desktop` — l'organisation travaille sur l'application installée (`System Settings.interface`) :
        # le lien passe alors par la page de rebond https déjà prévue pour cela (`/redirect`, schémas en liste
        # blanche, bouton de secours si l'application n'est pas installée). Jamais un `erp://` nu dans un e-mail :
        # beaucoup de clients de messagerie ne le rendent même pas cliquable.
        web_url = f"{self.desk_url}#/invite?{urlencode({'token': invite_token})}"
        if interface == "desktop":
            deep = f"erp://invite?{urlencode({'token': invite_token})}"
            accept_url = f"{self.base_url}/app/auth/redirect?{urlencode({'target': deep})}"
        else:
            accept_url = web_url
        return await self.send(
            to=to,
            subject=f"Vous êtes invité à rejoindre {tenant_name}",
            template="invitation",
            context={
                "tenant_name": tenant_name,
                "invited_by": invited_by,
                "accept_url": accept_url,
                "expires_hours": expires_hours,
            },
        )
