from __future__ import annotations
from pathlib import Path
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from xcore.sdk import get_logger

from ..utils.http import get_client_ip

logger = get_logger("xauth.middleware.geoip")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent


class GeoIPMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, db_path: str | None = None) -> None:
        super().__init__(app)
        self._reader: Any = None
        if db_path:
            self._init_reader(db_path)

    def _init_reader(self, db_path: str) -> None:
        resolved = Path(db_path)
        logger.info("abs path",resolved)
        if not resolved.is_absolute():
            abs_path = _PROJECT_ROOT / resolved
            
            if abs_path.exists():
                resolved = abs_path
        try:
            import geoip2.database
            self._reader = geoip2.database.Reader(str(resolved))
            logger.info("GeoIP database loaded from %s", resolved)
        except Exception:
            logger.warning(
                "GeoIP database not found at %s — geolocation disabled", resolved
            )

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        geo: dict[str, Any] = {"ip": get_client_ip(request)}
        if self._reader is not None and geo["ip"] not in ("unknown", "127.0.0.1", "::1"):
            try:
                resp = self._reader.city(geo["ip"])
                print(resp)
                if resp:
                    geo["country"] = resp.country.name or None
                    geo["country_code"] = resp.country.iso_code or None
                    geo["city"] = resp.city.name or None
                    geo["latitude"] = resp.location.latitude if resp.location else None
                    geo["longitude"] = resp.location.longitude if resp.location else None
                    geo["timezone"] = resp.location.time_zone if resp.location else None
                    geo["continent"] = resp.continent.name if resp.continent else None
                    geo["postal_code"] = resp.postal.code if resp.postal else None
            except Exception:
                logger.debug("GeoIP lookup failed for %s", geo["ip"])

        request.state.geo = geo

        response = await call_next(request)
        if geo.get("country_code"):
            response.headers["X-Geo-Country"] = geo["country_code"]
        if geo.get("city"):
            response.headers["X-Geo-City"] = geo["city"]
        return response
