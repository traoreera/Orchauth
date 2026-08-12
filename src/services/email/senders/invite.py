from __future__ import annotations

from ....utils.deeplink import wrap_bridge
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
        # Emballé dans la page de rebond https : un destinataire sans l'app
        # installée (le cas le plus fréquent pour une invitation) voit une
        # page normale plutôt qu'un lien erp:// mort (auth Constat 10).
        accept_url = wrap_bridge(self.base_url, f"erp://invite?token={invite_token}")
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
