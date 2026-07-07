from __future__ import annotations

import hashlib
import json
import secrets
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from xcore.sdk import get_logger

logger = get_logger("xauth.mfa")

from ..repositories.user import UserRepository


def _hash_backup_code(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


class MFAService:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    def _generate_backup_codes(self, count: int = 8) -> list[str]:
        return [secrets.token_hex(5).upper() for _ in range(count)]

    async def setup_totp(self, user_id: str) -> dict:
        """
        Génère un secret TOTP et des backup codes.
        Les backup codes sont stockés hachés en base. Retourne les codes en clair
        (unique occasion de les voir — l'utilisateur doit les sauvegarder).
        """
        try:
            import pyotp
        except ImportError:
            raise RuntimeError("pyotp is required for MFA. Install with: uv add pyotp")

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None:
            raise ValueError("User not found")

        secret = pyotp.random_base32()
        backup_codes_plain = self._generate_backup_codes()
        backup_codes_hashed = [_hash_backup_code(c) for c in backup_codes_plain]

        user.mfa_secret = secret
        user.mfa_backup_codes = json.dumps(backup_codes_hashed)
        await self._session.flush()
        logger.info("MFA TOTP setup initiated for user %s", user_id)

        totp = pyotp.TOTP(secret)
        uri = totp.provisioning_uri(name=user.email, issuer_name="xauth")

        # Génère le QR code en base64 PNG pour l'affichage dans l'app
        try:
            import base64
            import io
            import qrcode as _qrcode
            img = _qrcode.make(uri)
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            qr_b64 = base64.b64encode(buf.getvalue()).decode()
        except Exception:
            qr_b64 = None

        return {
            "secret": secret,
            "otpauth_url": uri,
            "qr_code": qr_b64,
            "backup_codes": backup_codes_plain,
        }

    async def verify_totp(self, user_id: str, code: str) -> bool:
        """
        Vérifie un code TOTP ou un backup code.
        Les backup codes sont à usage unique : une fois utilisé, il est supprimé.
        """
        try:
            import pyotp
        except ImportError:
            raise RuntimeError("pyotp is required for MFA.")

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None or user.mfa_secret is None:
            return False

        # 1. Vérification TOTP standard
        totp = pyotp.TOTP(user.mfa_secret)
        if totp.verify(code, valid_window=1):
            return True

        # 2. Vérification backup code
        if user.mfa_backup_codes:
            stored = json.loads(user.mfa_backup_codes)
            code_hash = _hash_backup_code(code.upper())
            if code_hash in stored:
                stored.remove(code_hash)
                user.mfa_backup_codes = json.dumps(stored)
                await self._session.flush()
                return True

        return False

    async def regenerate_backup_codes(self, user_id: str) -> list[str]:
        """Régénère les backup codes (invalide les anciens)."""
        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user is None:
            raise ValueError("User not found")
        if not user.mfa_enabled:
            raise ValueError("MFA is not enabled for this user")

        codes_plain = self._generate_backup_codes()
        user.mfa_backup_codes = json.dumps([_hash_backup_code(c) for c in codes_plain])
        await self._session.flush()
        logger.info("MFA backup codes regenerated for user %s", user_id)
        return codes_plain

    async def enable_mfa(self, user_id: str, code: str) -> bool:
        """Active MFA après confirmation du code TOTP."""
        valid = await self.verify_totp(user_id, code)
        if not valid:
            return False

        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user:
            user.mfa_enabled = True
            await self._session.flush()
        logger.info("MFA enabled for user %s", user_id)
        return True

    async def disable_mfa(self, user_id: str) -> None:
        repo = UserRepository(self._session)
        user = await repo.get(user_id)
        if user:
            user.mfa_enabled = False
            user.mfa_secret = None
            user.mfa_backup_codes = None
            await self._session.flush()
            logger.info("MFA disabled for user %s", user_id)
