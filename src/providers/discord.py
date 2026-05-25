from __future__ import annotations

import httpx

from .base import OAuthProvider, OAuthUserInfo


class DiscordProvider(OAuthProvider):
    name = "discord"
    auth_url = "https://discord.com/api/oauth2/authorize"
    token_url = "https://discord.com/api/oauth2/token"
    scopes = ["identify", "email"]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                "https://discord.com/api/users/@me",
                headers={"Authorization": f"Bearer {access_token}"},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

        email = data.get("email")
        if not email:
            raise ValueError("Discord n'a pas retourné d'adresse email.")

        avatar = None
        if data.get("avatar"):
            avatar = f"https://cdn.discordapp.com/avatars/{data['id']}/{data['avatar']}.png"

        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=str(data["id"]),
            email=email,
            name=data.get("global_name") or data.get("username"),
            avatar_url=avatar,
            raw=data,
        )
