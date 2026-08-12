from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

logger = get_logger("xauth.password")

from ..repositories.user import UserRepository
from .auth.password import _check_password_policy, get_pwd_context
from .events import XAuthEvents

_RESET_KEY_PREFIX = "xauth:pwd_reset:"
_RESET_TTL = 1800  # 30 minutes


class PasswordService:
    def __init__(self, session: AsyncSession, cache: Any, events: XAuthEvents | None = None) -> None:
        self._session = session
        self._cache = cache
        self._events = events

    # ── Forgot password ───────────────────────────────────────────────────────

    async def create_reset_token(self, email: str) -> str | None:
        """
        Génère un token de reset et le stocke en cache (TTL 30min).
        Retourne le token si l'email existe, None sinon — mais l'appelant
        ne doit PAS révéler cette distinction à l'utilisateur (anti-énumération).
        """
        repo = UserRepository(self._session)
        user = await repo.get_by_email(email)
        if user is None or not user.is_active:
            return None

        token = secrets.token_urlsafe(48)
        await self._cache.set(
            f"{_RESET_KEY_PREFIX}{token}",
            user.id,
            ttl=_RESET_TTL,
        )
        if self._events:
            await self._events.password_reset_requested(email=email)
        logger.info("Password reset token created for %s", email)
        return token

    async def reset_password(
        self,
        *,
        token: str,
        new_password: str,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_digit: bool = True,
    ) -> str:
        """Valide le token de reset, change le mot de passe, retourne l'email du user."""
        key = f"{_RESET_KEY_PREFIX}{token}"
        user_id = await self._cache.get(key)
        if user_id is None:
            raise ValueError("Token invalide ou expiré.")

        _check_password_policy(new_password, min_length, require_uppercase, require_digit)

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None or not user.is_active:
            raise ValueError("Utilisateur introuvable ou inactif.")

        user.hashed_password = get_pwd_context().hash(new_password)
        await self._session.flush()

        await self._cache.delete(key)
        if self._events:
            await self._events.password_reset_completed(email=user.email)
        logger.info("Password reset completed for %s", user.email)
        return user.email

    # ── Change password (utilisateur authentifié) ─────────────────────────────

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_digit: bool = True,
    ) -> None:
        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None:
            raise ValueError("Utilisateur introuvable.")

        if not user.hashed_password:
            raise ValueError(
                "Ce compte n'a pas de mot de passe. "
                "Utilisez 'Définir un mot de passe' à la place."
            )

        if not get_pwd_context().verify(current_password, user.hashed_password):
            raise ValueError("Mot de passe actuel incorrect.")

        _check_password_policy(new_password, min_length, require_uppercase, require_digit)

        if get_pwd_context().verify(new_password, user.hashed_password):
            raise ValueError("Le nouveau mot de passe doit être différent de l'actuel.")

        user.hashed_password = get_pwd_context().hash(new_password)
        await self._session.flush()
        if self._events:
            await self._events.password_changed(user_id=user_id)
        logger.info("Password changed for user %s", user_id)

    # ── Set password (comptes OAuth sans password) ────────────────────────────

    async def set_password(
        self,
        user_id: str,
        new_password: str,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_digit: bool = True,
    ) -> None:
        """Pour les utilisateurs OAuth qui n'ont pas encore de mot de passe."""
        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None:
            raise ValueError("Utilisateur introuvable.")

        if user.hashed_password:
            raise ValueError(
                "Ce compte a déjà un mot de passe. Utilisez 'Changer le mot de passe'."
            )

        _check_password_policy(new_password, min_length, require_uppercase, require_digit)
        user.hashed_password = get_pwd_context().hash(new_password)
        await self._session.flush()
        if self._events:
            await self._events.password_set(user_id=user_id)
        logger.info("Password set for user %s", user_id)


    async def verify_password(self, user_id: str, password: str) -> bool:
        """Vérifie si le mot de passe correspond à l'utilisateur."""
        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None or not user.hashed_password:
            return False
        return get_pwd_context().verify(password, user.hashed_password)
