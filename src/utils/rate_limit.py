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


class RateLimiter:
    def __init__(self, cache: Any, max_calls: int, period: int) -> None:
        self._cache = cache
        self._max_calls = max_calls
        self._period = period

    def _key(self, route: str, ip: str) -> str:
        window = int(time.time()) // self._period
        return f"rl:{route}:{ip}:{window}"

    async def _check(self, route: str, ip: str) -> None:
        if self._cache is None:
            return
        key = self._key(route, ip)
        try:
            count = await self._cache.get(key)
            current = int(count) if count else 0
            if current >= self._max_calls:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please try again shortly.",
                    headers={"Retry-After": str(self._period)},
                )
            await self._cache.set(key, current + 1, ttl=self._period * 2)
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
