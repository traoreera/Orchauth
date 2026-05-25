from __future__ import annotations

import httpx

from .base import OAuthProvider, OAuthUserInfo


class MicrosoftProvider(OAuthProvider):
    name = "microsoft"
    auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    scopes = ["openid", "email", "profile", "User.Read"]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

        email = data.get("mail") or data.get("userPrincipalName")
        if not email:
            raise ValueError("Microsoft n'a pas retourné d'adresse email.")

        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=data["id"],
            email=email,
            name=data.get("displayName"),
            avatar_url=None,  # nécessite un appel séparé /me/photo
            raw=data,
        )
