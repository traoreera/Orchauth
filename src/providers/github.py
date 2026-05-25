from __future__ import annotations

import httpx

from .base import OAuthProvider, OAuthUserInfo


class GitHubProvider(OAuthProvider):
    name = "github"
    auth_url = "https://github.com/login/oauth/authorize"
    token_url = "https://github.com/login/oauth/access_token"
    scopes = ["read:user", "user:email"]

    async def get_user_info(self, access_token: str) -> OAuthUserInfo:
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/vnd.github+json",
        }
        async with httpx.AsyncClient() as client:
            user_resp = await client.get(
                "https://api.github.com/user",
                headers=headers,
                timeout=10,
            )
            user_resp.raise_for_status()
            data = user_resp.json()

            # L'email peut être null sur le profil — on cherche dans /user/emails
            email = data.get("email")
            if not email:
                emails_resp = await client.get(
                    "https://api.github.com/user/emails",
                    headers=headers,
                    timeout=10,
                )
                if emails_resp.status_code == 200:
                    emails = emails_resp.json()
                    primary = next(
                        (e["email"] for e in emails if e.get("primary") and e.get("verified")),
                        None,
                    )
                    email = primary or (emails[0]["email"] if emails else None)

        if not email:
            raise ValueError("GitHub n'a pas retourné d'adresse email vérifiée.")

        return OAuthUserInfo(
            provider=self.name,
            provider_user_id=str(data["id"]),
            email=email,
            name=data.get("name") or data.get("login"),
            avatar_url=data.get("avatar_url"),
            raw=data,
        )
