from .base import OAuthProvider, OAuthUserInfo
from .google import GoogleProvider
from .github import GitHubProvider
from .discord import DiscordProvider
from .microsoft import MicrosoftProvider

__all__ = [
    "OAuthProvider",
    "OAuthUserInfo",
    "GoogleProvider",
    "GitHubProvider",
    "DiscordProvider",
    "MicrosoftProvider",
]
