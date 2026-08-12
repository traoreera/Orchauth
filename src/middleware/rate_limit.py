"""
Orchauth — RateLimitMiddleware ASGI

Sliding-window par IP sur toutes les routes xauth.
Fail-open si le cache est indisponible.

Limites par défaut :
    /app/auth/login           → 10 req / 60s
    /app/auth/register        → 5  req / 60s
    /app/auth/verify-mfa      → 5  req / 60s
    /app/auth/password/forgot → 3  req / 300s
    /app/auth/password/reset  → 5  req / 300s
    /app/auth/oauth/*         → 30 req / 60s
    tout le reste             → 300 req / 60s
"""
from __future__ import annotations

import time
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from xcore.sdk import get_logger

from ..utils.http import get_client_ip

logger = get_logger("xauth.middleware.rate_limit")

_DEFAULT_RULES: list[tuple[str, int, int]] = [
    ("/app/auth/login",           5,  60),
    ("/app/auth/register",        3,  60),
    ("/app/auth/verify-mfa",      3,  60),
    ("/app/auth/password/forgot", 1, 120),
    ("/app/auth/password/reset",  3, 300),
    ("/app/auth/oauth/",         20,  60),
    ("/app/auth/mfa/",            10, 60),
]
_DEFAULT_FALLBACK = (300, 60)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Middleware ASGI de rate-limiting par IP (sliding-window).

    Args:
        app:          ASGI app
        cache:        service cache xcore (get/set async)
        route_limits: liste de tuples (prefix, max_calls, period_seconds)
                    urchargée via integration.yaml si besoin
    """

    def __init__(
        self,
        app: Any,
        cache: Any = None,
        route_limits: list[tuple[str, int, int]] | None = None,
    ) -> None:
        super().__init__(app)
        self._cache = cache() if callable(cache) else cache
        self._rules: list[tuple[str, int, int]] = route_limits or _DEFAULT_RULES
        self._fallback_max, self._fallback_period = _DEFAULT_FALLBACK

    # ── helpers ──────────────────────────────────────────────────────────────

    def _match(self, path: str) -> tuple[int, int]:
        for prefix, max_calls, period in self._rules:
            if path.startswith(prefix):
                return max_calls, period
        return self._fallback_max, self._fallback_period

    def _cache_key(self, route: str, ip: str, period: int) -> str:
        window = int(time.time()) // period
        return f"rl:{route}:{ip}:{window}"

    async def _check(self, path: str, ip: str) -> tuple[bool, int]:
        """Retourne (allowed, retry_after)."""
        if self._cache is None:
            return True, 0

        cache = self._cache
        if not hasattr(cache, "get") or not hasattr(cache, "set"):
            logger.warning("rate_limit cache not available, skipping")
            return True, 0

        max_calls, period = self._match(path)
        key = self._cache_key(path, ip, period)

        try:
            raw = await cache.get(key)
            count = int(raw) if raw else 0
            if count >= max_calls:
                return False, period
            await cache.set(key, count + 1, ttl=period * 2)
        except Exception as exc:
            logger.error("rate_limit cache error: %s", exc)
            return True, 0

        return True, 0

    # ── dispatch ─────────────────────────────────────────────────────────────

    async def dispatch(self, request: Request, call_next) -> Response:
        ip = get_client_ip(request)
        allowed, retry_after = await self._check(request.url.path, ip)

        if not allowed:
            logger.warning("rate_limit hit: ip=%s path=%s", ip, request.url.path)
            return JSONResponse(
                status_code=429,
                content={"error": "too_many_requests", "detail": "Too many requests. Please try again shortly."},
                headers={"Retry-After": str(retry_after)},
            )

        return await call_next(request)
