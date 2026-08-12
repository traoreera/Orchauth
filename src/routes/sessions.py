from __future__ import annotations

from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from xcore.kernel.api import AuthPayload, get_current_user

from ..repositories.session import SessionRepository
from ..services.auth import AuthenticationService
from ..services.token import TokenService
from ..utils.http import get_client_ip
from ..utils.rate_limit import RateLimiter


class SessionResponse(BaseModel):
    id: str
    tenant_id: str | None
    ip_address: str | None
    device_fingerprint: str | None
    last_seen: str
    expires_at: str
    is_current: bool = False

    model_config = {"from_attributes": True}


class VerifyMFARequest(BaseModel):
    mfa_token: str
    code: str
    device_fingerprint: str | None = None


def sessions_router(db: Any, token_service: TokenService, cache: Any = None) -> APIRouter:
    router = APIRouter(tags=["sessions"])

    _rl_verify_mfa = RateLimiter(cache, max_calls=5, period=60).for_route("verify-mfa")

    @router.post("/auth/verify-mfa")
    async def verify_mfa(body: VerifyMFARequest, request: Request, _rl: None = Depends(_rl_verify_mfa)) -> Any:
        """
        Deuxième étape du login MFA.
        Vérifie le challenge JWT (mfa_token, 5 min) + code TOTP.
        Crée la session réelle et retourne les tokens définitifs.
        """
        ip = get_client_ip(request)
        async with db.session() as session:
            svc = AuthenticationService(session, token_service, cache=cache)
            try:
                result = await svc.verify_mfa_and_issue_token(
                    mfa_token=body.mfa_token,
                    totp_code=body.code,
                    ip_address=ip,
                    device_fingerprint=body.device_fingerprint,
                )
                await session.commit()
                return result
            except ValueError as exc:
                raise HTTPException(status_code=401, detail=str(exc))

    @router.get("/auth/sessions", response_model=List[SessionResponse])
    async def list_sessions(
        current_user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """Liste toutes les sessions actives de l'utilisateur connecté."""
        async with db.session() as session:
            repo = SessionRepository(session)
            sessions = await repo.get_active_sessions_for_user(current_user["sub"])
            return [
                {
                    "id": s.id,
                    "tenant_id": s.tenant_id,
                    "ip_address": s.ip_address,
                    "device_fingerprint": s.device_fingerprint,
                    "last_seen": s.last_seen.isoformat(),
                    "expires_at": s.expires_at.isoformat(),
                }
                for s in sessions
            ]

    @router.delete("/auth/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_session(
        session_id: str,
        current_user: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Révoque une session spécifique (déconnexion d'un appareil)."""
        async with db.session() as session:
            repo = SessionRepository(session)
            target = await repo.get(session_id)
            if target is None or target.user_id != current_user["sub"]:
                raise HTTPException(status_code=404, detail="Session not found")
            if target.is_revoked:
                raise HTTPException(status_code=400, detail="Session already revoked")

            # Blacklister le JTI si présent
            if cache and target.last_jti:
                ttl = token_service.access_expire * 60 + 30
                await cache.set(f"xauth:jti_bl:{target.last_jti}", "1", ttl=ttl)

            target.is_revoked = True
            await session.commit()

    @router.delete("/auth/sessions", status_code=status.HTTP_204_NO_CONTENT)
    async def revoke_all_sessions(
        current_user: AuthPayload = Depends(get_current_user),
    ) -> None:
        """Révoque toutes les sessions actives (logout de tous les appareils)."""
        async with db.session() as session:
            repo = SessionRepository(session)
            sessions = await repo.get_active_sessions_for_user(current_user["sub"])

            for s in sessions:
                if cache and s.last_jti:
                    ttl = token_service.access_expire * 60 + 30
                    await cache.set(f"xauth:jti_bl:{s.last_jti}", "1", ttl=ttl)

            await repo.revoke_all_for_user(current_user["sub"])
            await session.commit()

    return router
