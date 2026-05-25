from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from jose import JWTError, jwt

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

    def create_access_token(
        self,
        user_id: str,
        tenant_id: Optional[str] = None,
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
            raise ValueError(f"Token invalide : {exc}") from exc
        if payload.get("type") != "access":
            raise ValueError("Ce token n'est pas un access token")
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
            raise ValueError(f"Token invalide : {exc}") from exc
        if payload.get("type") != "mfa_challenge":
            raise ValueError("Ce token n'est pas un challenge MFA")
        return payload
