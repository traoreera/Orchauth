from __future__ import annotations

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
        accept_url = f"{self.base_url}/xauth/invites/accept?token={invite_token}"
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
