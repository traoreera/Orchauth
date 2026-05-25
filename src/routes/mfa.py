from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..services.mfa import MFAService


class VerifyMFARequest(BaseModel):
    code: str


class EnableMFARequest(BaseModel):
    code: str


class MfaVerifyLoginRequest(BaseModel):
    mfa_token: str
    code: str


def mfa_router(db: Any, token_service: Optional[Any] = None) -> APIRouter:
    router = APIRouter(prefix="/mfa", tags=["mfa"])

    @router.post("/verify-login")
    async def verify_mfa_login(body: MfaVerifyLoginRequest) -> Any:
        if token_service is None:
            raise HTTPException(status_code=503, detail="Service non configuré")
        try:
            claims = token_service.verify_mfa_challenge_token(body.mfa_token)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc))

        user_id = claims["sub"]
        tenant_id = claims.get("tenant_id")

        async with db.session() as session:
            svc = MFAService(session)
            valid = await svc.verify_totp(user_id, body.code)
            if not valid:
                raise HTTPException(
                    status_code=400, detail="Code TOTP invalide ou expiré"
                )

            from ..models.session import Session
            from ..repositories.session import SessionRepository
            access_token, jti = token_service.create_access_token(
                user_id=user_id, tenant_id=tenant_id
            )
            refresh_plain = token_service.create_refresh_token()
            refresh_hashed = token_service.hash_token(refresh_plain)

            sess = Session(
                user_id=user_id,
                tenant_id=tenant_id,
                refresh_token=refresh_hashed,
                expires_at=datetime.now(tz=timezone.utc)
                + timedelta(days=token_service._refresh_expire),
                last_jti=jti,
            )
            await SessionRepository(session).save(sess)
            await session.commit()

        return {
            "access_token": access_token,
            "refresh_token": refresh_plain,
            "token_type": "bearer",
            "user_id": user_id,
            "tenant_id": tenant_id,
            "mfa_required": False,
            "tenants": None,
        }

    @router.post("/setup")
    async def setup_totp(
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = MFAService(session)
            try:
                result = await svc.setup_totp(user["sub"])
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=404, detail=str(exc))
            except RuntimeError as exc:
                raise HTTPException(status_code=500, detail=str(exc))

    @router.post("/enable")
    async def enable_mfa(
        body: EnableMFARequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = MFAService(session)
            success = await svc.enable_mfa(user["sub"], body.code)
            if not success:
                raise HTTPException(status_code=400, detail="Invalid TOTP code")
            await session.commit()
            return {"mfa_enabled": True}

    @router.post("/verify")
    async def verify_totp(
        body: VerifyMFARequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            svc = MFAService(session)
            valid = await svc.verify_totp(user["sub"], body.code)
            return {"valid": valid}

    @router.delete("/", status_code=status.HTTP_204_NO_CONTENT)
    async def disable_mfa(
        user: AuthPayload = Depends(get_current_user),
    ) -> None:
        async with db.session() as session:
            svc = MFAService(session)
            await svc.disable_mfa(user["sub"])
            await session.commit()

    return router
