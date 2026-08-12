from __future__ import annotations

import httpx

from .base import OAuthProvider, OAuthUserInfo


class GoogleProvider(OAuthProvider):
    name = "google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    # gmail.modify : lecture/écriture messages/threads/labels/brouillons —
    # tout sauf la suppression PERMANENTE (bypass corbeille), qui exige le
    # scope restreint https://mail.google.com/ (soumis à vérification
    # Google/CASA pour une app en prod, volontairement pas demandé ici :
    # GoogleServiceClient.delete_message existe pour ceux qui l'ajoutent).
    # calendar : accès complet Calendar (agendas + calendarList + events),
    # plus large que calendar.events pour couvrir create/update/delete
    # calendar et calendarList côté GoogleServiceClient.
    scopes = [
        "openid",
        "email",
        "profile",
        "https://www.googleapis.com/auth/gmail.modify",
        "https://www.googleapis.com/auth/calendar",
    ]

    def get_auth_url(self, state: str, extra_params=None) -> str:
        return super().get_auth_url(state, {"access_type": "offline", "prompt": "consent"})

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://www.googleapis.com/oauth2/v3/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=data["sub"],
            email=data["email"],
            name=data.get("name"),
            avatar_url=data.get("picture"),
            raw=data,
        )
