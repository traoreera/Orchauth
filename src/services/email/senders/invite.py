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
    ) -> bool:
        # Lien WEB vers la page d'invitation du Desk (`#/invite?token=…`), jamais un deep-link `erp://` : un invité sans application ouvre son navigateur.
        accept_url = f"{self.desk_url}#/invite?{urlencode({'token': invite_token})}"
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
