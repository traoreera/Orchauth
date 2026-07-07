from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from xcore.kernel.api import AuthPayload, get_current_user

from ..schemas.auth import (
    LoginRequest,
    LogoutRequest,
    RefreshRequest,
    RegisterRequest,
    SelectTenantRequest,
    SetupCreateRequest,
    SetupJoinRequest,
    TokenResponse,
    UserResponse,
)
from ..services.auth import (
    AuthenticationService,
    OnboardingService,
    RegistrationService,
    SessionService,
)
from ..services.email import AuthEmailService
from ..services.events import XAuthEvents
from ..services.token import TokenService
from ..utils.http import get_client_ip
from ..utils.rate_limit import RateLimiter


def auth_router(
    db,
    token_service: TokenService,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
    cache=None,
    user_role_name: str = "user",
    admin_role_name: str = "admin",
) -> APIRouter:
    router = APIRouter(tags=["auth"])

    _rl_login    = RateLimiter(cache, max_calls=5,  period=60).for_route("login")
    _rl_register = RateLimiter(cache, max_calls=3,  period=60).for_route("register")
    _rl_refresh  = RateLimiter(cache, max_calls=15, period=60).for_route("refresh")

    @router.post(
        "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
    )
    async def register(body: RegisterRequest, _rl: None = Depends(_rl_register)):
        async with db.session() as session:
            svc = RegistrationService(session, token_service, events)
            try:
                user = await svc.register(
                    email=body.email,
                    password=body.password,
                )
                await session.commit()
                await session.refresh(user)
                email_service.auth.queue_template(
                    to=user.email,
                    subject=f"Bienvenue sur {email_service.auth.app_name}",
                    template="welcome",
                    context={
                        "username": user.email,
                        "login_url": f"{email_service.auth.base_url}/login",
                    },
                )
                return user
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.post("/login", response_model=TokenResponse)
    async def login(body: LoginRequest, request: Request, _rl: None = Depends(_rl_login)):
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = AuthenticationService(session, token_service, events, cache=cache)
            try:
                result = await svc.login(
                    email=body.email,
                    password=body.password,
                    tenant_id=body.tenant_id,
                    ip_address=ip,
                )
                await session.commit()
                response = JSONResponse(content=result)
                if result.get("access_token"):
                    response.set_cookie(
                        key="access_token",
                        value=result["access_token"],
                        httponly=True,
                        secure=True,
                        samesite="strict",
                        max_age=1800,
                    )
                return response
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.post("/refresh", response_model=TokenResponse)
    async def refresh(body: RefreshRequest, request: Request, _rl: None = Depends(_rl_refresh)):
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = SessionService(session, token_service, events, cache=cache)
            try:
                result = await svc.refresh(
                    refresh_token=body.refresh_token, ip_address=ip
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
    async def logout(body: LogoutRequest):
        async with db.session() as session:
            svc = SessionService(session, token_service, events, cache=cache)
            await svc.logout(body.refresh_token)
            await session.commit()

    @router.post("/setup/create", response_model=TokenResponse)
    async def setup_create(body: SetupCreateRequest, request: Request):
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = OnboardingService(session, token_service, events, owner_role_name=admin_role_name)
            try:
                result = await svc.setup_create_tenant(
                    refresh_token=body.refresh_token,
                    name=body.name,
                    slug=body.slug,
                    ip_address=ip,
                )
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

        if events and result.get("tenant_id"):
            await events.tenant_created(
                result["tenant_id"], result["user_id"], body.slug
            )
        return result

    @router.post("/setup/join", response_model=TokenResponse)
    async def setup_join(body: SetupJoinRequest, request: Request):
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = OnboardingService(session, token_service, events)
            try:
                result = await svc.setup_join_tenant(
                    refresh_token=body.refresh_token,
                    invite_token=body.invite_token,
                    ip_address=ip,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.post("/select-tenant", response_model=TokenResponse)
    async def select_tenant(body: SelectTenantRequest, request: Request):
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = AuthenticationService(session, token_service, events)
            try:
                result = await svc.select_tenant(
                    refresh_token=body.refresh_token,
                    tenant_id=body.tenant_id,
                    ip_address=ip,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

    @router.get("/me", response_model=UserResponse)
    async def me(current_user: AuthPayload = Depends(get_current_user)):
        from ..repositories.user import UserRepository

        async with db.session() as session:
            repo = UserRepository(session)
            user = await repo.get(current_user["sub"])
            if user is None:
                raise HTTPException(status_code=404, detail="User not found")
            return user

    return router
