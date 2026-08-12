"""
Chiffrement au repos des jetons d'accès aux API tierces (Gmail/Calendar via
Google, potentiellement d'autres providers plus tard).

Distinct des refresh tokens de session xauth : ceux-là sont révocables côté
plateforme et scopés à xauth lui-même. Un access/refresh token Google donne
un accès direct et durable au compte réel de l'utilisateur (envoi d'email en
son nom, lecture/écriture de son agenda) — jamais stocké en clair.
"""

from __future__ import annotations

from typing import Optional

from cryptography.fernet import Fernet, InvalidToken
from xcore.sdk import get_logger

logger = get_logger("xauth.token_crypto")


class OAuthTokenCipher:
    """
    Wrapper Fernet (AES128-CBC + HMAC) pour les jetons OAuth stockés sur
    `OAuthAccount`. Sans clé configurée, `encrypt`/`decrypt` retournent
    `None` — le stockage de jetons est alors désactivé plutôt que de se
    replier sur du texte en clair (jamais de fallback silencieux vers du
    stockage non chiffré).
    """

    def __init__(self, key: Optional[str]) -> None:
        self._fernet: Optional[Fernet] = None
        if key:
            try:
                self._fernet = Fernet(key.encode() if isinstance(key, str) else key)
            except Exception as exc:
                logger.error(
                    "XAUTH_OAUTH_TOKEN_KEY invalide (doit être une clé Fernet "
                    "base64 32 octets, ex. Fernet.generate_key()) : %s", exc,
                )

    @property
    def available(self) -> bool:
        return self._fernet is not None

    def encrypt(self, plaintext: Optional[str]) -> Optional[str]:
        if not plaintext or self._fernet is None:
            return None
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, ciphertext: Optional[str]) -> Optional[str]:
        if not ciphertext or self._fernet is None:
            return None
        try:
            return self._fernet.decrypt(ciphertext.encode()).decode()
        except InvalidToken:
            logger.warning("Jeton OAuth illisible (clé rotée ou donnée corrompue).")
            return None
