from __future__ import annotations

import httpx

from .base import OAuthProvider, OAuthUserInfo


class GoogleProvider(OAuthProvider):
    name = "google"
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url = "https://oauth2.googleapis.com/token"
    scopes = ["openid", "email", "profile"]

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
