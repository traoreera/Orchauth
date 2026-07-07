from __future__ import annotations

import re

_JTI_BLACKLIST_PREFIX = "xauth:jti_bl:"


def _get_password_context():
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
    except ImportError:
        pass
    try:
        from passlib.context import CryptContext

        return CryptContext(schemes=["bcrypt"], deprecated="auto")
    except ImportError:
        raise RuntimeError("passlib is required. Install with: uv add passlib[argon2]")


_pwd_context = None


def get_pwd_context():
    global _pwd_context
    if _pwd_context is None:
        _pwd_context = _get_password_context()
    return _pwd_context


def _check_password_policy(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_digit: bool = True,
) -> None:
    if len(password) < min_length:
        raise ValueError(f"Password must be at least {min_length} characters long")
    if require_uppercase and not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter")
    if require_digit and not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit")
