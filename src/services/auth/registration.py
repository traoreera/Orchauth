from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

from ...models.user import User
from ...repositories.user import UserRepository
from ..audit import AuditService
from ..events import XAuthEvents
from ..token import TokenService
from .password import _check_password_policy, get_pwd_context

logger = get_logger(__name__)


class RegistrationService:
    def __init__(
        self,
        session: AsyncSession,
        token_service: TokenService,
        events: XAuthEvents | None = None,
    ) -> None:
        self._session = session
        self._token = token_service
        self._events = events

    async def register(
        self,
        email: str,
        password: str,
        min_length: int = 8,
        require_uppercase: bool = True,
        require_digit: bool = True,
    ) -> User:
        _check_password_policy(
            password,
            min_length=min_length,
            require_uppercase=require_uppercase,
            require_digit=require_digit,
        )

        user_repo = UserRepository(self._session)
        existing = await user_repo.get_by_email(email)
        if existing is not None:
            raise ValueError("Email already registered")

        hashed = get_pwd_context().hash(password)
        user = User(email=email, hashed_password=hashed)
        await user_repo.save(user)
        logger.info("User registered: %s", email)

        audit = AuditService(self._session)
        await audit.log_event(
            action="user.registered",
            user_id=user.id,
            resource="user",
            resource_id=user.id,
        )

        if self._events:
            await self._events.user_registered(
                user_id=user.id,
                email=user.email,
                tenant_id=None,
            )

        return user

    async def verify_token(self, token: str) -> dict[str, Any]:
        return self._token.verify_access_token(token)
