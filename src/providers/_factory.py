from __future__ import annotations

from ..providers import (
    DiscordProvider,
    GitHubProvider,
    GoogleProvider,
    MicrosoftProvider,
)
from ..providers.base import OAuthProvider


def build_oauth_providers(
    env: dict, base_url: str = "http://localhost:8000"
) -> dict[str, OAuthProvider]:
    base_url = base_url.rstrip("/")
    providers: dict[str, OAuthProvider] = {}

    _registry = [
        ("google", GoogleProvider, "OAUTH_GOOGLE_CLIENT_ID", "OAUTH_GOOGLE_CLIENT_SECRET"),
        ("github", GitHubProvider, "OAUTH_GITHUB_CLIENT_ID", "OAUTH_GITHUB_CLIENT_SECRET"),
        ("discord", DiscordProvider, "OAUTH_DISCORD_CLIENT_ID", "OAUTH_DISCORD_CLIENT_SECRET"),
        ("microsoft", MicrosoftProvider, "OAUTH_MICROSOFT_CLIENT_ID", "OAUTH_MICROSOFT_CLIENT_SECRET"),
    ]

    for name, cls, id_key, secret_key in _registry:
        client_id = env.get(id_key, "")
        client_secret = env.get(secret_key, "")
        if client_id and client_secret:
            redirect_uri = f"{base_url}/app/auth/oauth/{name}/callback"
            providers[name] = cls(client_id, client_secret, redirect_uri)

    return providers
