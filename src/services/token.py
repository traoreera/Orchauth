from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from jose import JWTError, jwt
from xcore.sdk import get_logger

logger = get_logger("xauth.token")
ALGORITHM = "RS256"


class TokenService:
    """
    JWT RS256 avec fichiers PEM.
    Les chemins sont injectés depuis self.ctx.env (plugin.yaml → .env).
    """

    def __init__(
        self,
        private_key_path: str,
        public_key_path: str,
        access_expire_minutes: int = 15,
        refresh_expire_days: int = 7,
    ) -> None:
        self._private_key = Path(private_key_path).read_text()
        self._public_key = Path(public_key_path).read_text()
        self._access_expire = access_expire_minutes
        self._refresh_expire = refresh_expire_days

    @property
    def access_expire(self) -> int:
        return self._access_expire

    @property
    def refresh_expire(self) -> int:
        return self._refresh_expire

    def create_access_token(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
        email: Optional[str] = None,
        roles: Optional[list[str]] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> tuple[str, str]:
        now = datetime.now(tz=timezone.utc)
        jti = str(uuid4())
        payload: dict[str, Any] = {
            "sub": user_id,
            "jti": jti,
            "iat": now,
            "exp": now + timedelta(minutes=self._access_expire),
            "type": "access",
        }
        if tenant_id:
            payload["tenant_id"] = tenant_id
        if email:
            payload["email"] = email
        if roles:
            payload["roles"] = roles
        if extra:
            payload.update(extra)
        token = jwt.encode(payload, self._private_key, algorithm=ALGORITHM)
        return token, jti

    def create_refresh_token(self) -> str:
        return secrets.token_urlsafe(64)

    def hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def verify_access_token(self, token: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(token, self._public_key, algorithms=[ALGORITHM])
        except JWTError as exc:
            logger.warning("Access token verification failed: %s", exc)
            raise ValueError(f"Invalid token: {exc}") from exc
        if payload.get("type") != "access":
            logger.warning("Token type mismatch: expected 'access', got '%s'", payload.get("type"))
            raise ValueError("Not an access token")
        logger.debug("Access token verified for user %s", payload.get("sub"))
        return payload

    def create_mfa_challenge_token(
        self, user_id: str, tenant_id: Optional[str] = None
    ) -> str:
        now = datetime.now(tz=timezone.utc)
        payload: dict[str, Any] = {
            "sub": user_id,
            "jti": str(uuid4()),
            "iat": now,
            "exp": now + timedelta(minutes=5),
            "type": "mfa_challenge",
        }
        if tenant_id:
            payload["tenant_id"] = tenant_id
        return jwt.encode(payload, self._private_key, algorithm=ALGORITHM)

    def verify_mfa_challenge_token(self, token: str) -> dict[str, Any]:
        try:
            payload = jwt.decode(token, self._public_key, algorithms=[ALGORITHM])
        except JWTError as exc:
            logger.warning("MFA challenge token verification failed: %s", exc)
            raise ValueError(f"Invalid MFA challenge token: {exc}") from exc
        if payload.get("type") != "mfa_challenge":
            logger.warning("Token type mismatch: expected 'mfa_challenge', got '%s'", payload.get("type"))
            raise ValueError("Not an MFA challenge token")
        logger.debug("MFA challenge token verified for user %s", payload.get("sub"))
        return payload
