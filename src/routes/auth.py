from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status

from ..repositories.user import UserRepository
from ..schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    SelectTenantRequest,
    TokenResponse,
    UserResponse,
)
from ..services.auth import AuthService
from ..services.token import TokenService

def _extract_ip(request: Request) -> str:
    if forwarded := request.headers.get("x-forwarded-for"):
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def auth_router(auth_service: AuthService, token_service: TokenService, db: Any = None) -> APIRouter:
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

        user_id = claims["sub"]

        if db is not None:
            async with db.session() as session:
                user = await UserRepository(session).get(user_id)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            return {
                "id": user.id,
                "email": user.email,
                "is_active": user.is_active,
                "mfa_enabled": user.mfa_enabled,
                "has_password": bool(user.hashed_password),
            }

        # fallback si db non injecté — utilise les claims du JWT
        return {
            "id": user_id,
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
