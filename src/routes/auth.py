from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,SelectTenantRequest
)
from ..services.auth import AuthService
from ..services.token import TokenService

def _extract_ip(request: Request) -> str:
    if forwarded := request.headers.get("x-forwarded-for"):
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def auth_router(auth_service: AuthService, token_service: TokenService) -> APIRouter:
    router = APIRouter(tags=["auth"])

    @router.post(
        "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
    )
    async def register(body: RegisterRequest) -> Any:
        try:
            user = await auth_service.register(
                email=body.email,
                password=body.password,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return user

    @router.post("/login", response_model=TokenResponse)
    async def login(body: LoginRequest, request: Request) -> Any:
        ip = _extract_ip(request)
        try:
            result = await auth_service.login(
                email=body.email,
                password=body.password,
                tenant_id=body.tenant_id,
                ip_address=ip,
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        return result

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(body: RefreshRequest, request: Request) -> Any:
        ip = _extract_ip(request)
        try:
            result = await auth_service.refresh(
                refresh_token=body.refresh_token, ip_address=ip
            )
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))
        return result

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(body: LogoutRequest) -> None:
        await auth_service.logout(body.refresh_token)

    @router.get("/me", response_model=UserResponse)
    async def me(request: Request) -> Any:
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = auth_header[7:]
        try:
            claims = token_service.verify_access_token(token)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

        from ..repositories.user import UserRepository

        # We can't easily get the session here without DI, so return claims
        # In a real setup you'd inject the session; for now return from claims
        return {
            "id": claims["sub"],
            "email": claims.get("email", ""),
            "is_active": True,
            "mfa_enabled": False,
        }

    @router.post("/select-tenant", response_model=TokenResponse)
    async def select_tenant(body: SelectTenantRequest, request: Request):
        ip = _extract_ip(request)
        try:
            result = await auth_service.select_tenant(
                refresh_token=body.refresh_token,
                tenant_id=body.tenant_id,
                ip_address=ip,
            )
            return result
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    return router
