from __future__ import annotations

from fastapi import Request

TRUSTED_PROXIES = {
    "127.0.0.1", "::1", "10.0.0.0/8",
    "172.16.0.0/12", "192.168.0.0/16",
}


def get_client_ip(request: Request) -> str:
    client_ip = request.client.host if request.client else None
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded and client_ip and any(
        client_ip.startswith(p.rstrip("0/").rstrip("/")) for p in TRUSTED_PROXIES
    ):
        return forwarded.split(",")[0].strip()
    return client_ip or "unknown"
