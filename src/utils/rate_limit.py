"""Rate limiter par IP basé sur le cache xcore (Redis ou memory).

Usage dans les routes :
    rate_limit = RateLimiter(cache, max_calls=10, period=60)

    @router.post("/login")
    async def login(request: Request, _: None = Depends(rate_limit.for_route("login"))):
        ...
"""

from __future__ import annotations

import time
from typing import Any, Callable

from fastapi import HTTPException, Request, status
from xcore.sdk import get_logger

from .http import get_client_ip

logger = get_logger("xauth.ratelimit")


class RateLimitPolicy:
    """Le bloc `rate_limit:` du manifeste : `enabled: false` désactive la limitation (développement, tests), `routes: {login: [10, 60]}` change les bornes d'une
    route (`[appels, secondes]`). Un état de PROCESSUS : xauth n'a qu'une instance par hôte, et les routes (créées avant ou après) le lisent à chaque appel."""

    enabled: bool = True
    routes: dict[str, tuple[int, int]] = {}

    @classmethod
    def configure(cls, raw: Any) -> None:
        raw = raw if isinstance(raw, dict) else {}
        cls.enabled = raw.get("enabled", True) is not False
        cls.routes = {
            str(name): (int(limit[0]), int(limit[1]))
            for name, limit in (raw.get("routes") or {}).items()
            if isinstance(limit, (list, tuple)) and len(limit) == 2 and all(isinstance(n, int) and not isinstance(n, bool) and n > 0 for n in limit)
        }


class RateLimiter:
    def __init__(self, cache: Any, max_calls: int, period: int) -> None:
        self._cache = cache
        self._max_calls = max_calls
        self._period = period

    def _key(self, route: str, ip: str, period: int) -> str:
        window = int(time.time()) // period
        return f"rl:{route}:{ip}:{window}"

    async def _check(self, route: str, ip: str) -> None:
        if self._cache is None or not RateLimitPolicy.enabled:
            return
        max_calls, period = RateLimitPolicy.routes.get(route, (self._max_calls, self._period))
        key = self._key(route, ip, period)
        try:
            count = await self._cache.get(key)
            current = int(count) if count else 0
            if current >= max_calls:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again shortly.",
                    headers={"Retry-After": str(period)},
                )
            await self._cache.set(key, current + 1, ttl=period * 2)
        except HTTPException:
            raise
        except Exception:
            logger.exception("Cache error, blocking request")
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Service temporarily unavailable",
            )

    def for_route(self, route: str) -> Callable:
        async def _dep(request: Request) -> None:
            await self._check(route, get_client_ip(request))

        return _dep
