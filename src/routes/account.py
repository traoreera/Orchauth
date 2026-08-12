from __future__ import annotations

from typing import Any, Callable, Optional,TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from xcore.kernel.api import AuthPayload, get_current_user

from ..repositories.user import UserRepository
from ..services.auth.password import _check_password_policy, get_pwd_context
from ..services.mfa import MFAService

from ..services.events import XAuthEvents
from ..services.auth.session import SessionService as Ss

if TYPE_CHECKING:
    from ..services.token import TokenService
    from xcore.kernel.events import EventBus as EB

class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    password: str
    opt_code: str | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    opt_code: str | None = None


def account_router(db: Any, call_plugin:Callable, event_bus:Optional["EB"]=None, token_service:Optional["TokenService"]=None) -> APIRouter:
    router = APIRouter(prefix="/account", tags=["account"])

    @router.patch("/email", status_code=status.HTTP_200_OK)
    async def change_email(
        body: ChangeEmailRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            repo = UserRepository(session)
            u = await repo.get(user["sub"])
            if not u:
                raise HTTPException(status_code=404, detail="Utilisateur introuvable")

            # verifie si l'utilisateur a activé la MFA, si oui, il faut vérifier le code OTP
            if u.mfa_enabled:
                if not body.opt_code:
                    raise HTTPException(status_code=400, detail="Code OTP requis pour changer l'email")

                mfa_service = MFAService(session)

                if not await mfa_service.verify_totp(user_id=u.id, code=body.opt_code):
                    raise HTTPException(status_code=400, detail="Code OTP incorrect")

            # Vérifie le mot de passe actuel
            if not u.hashed_password or not get_pwd_context().verify(body.password, u.hashed_password):
                raise HTTPException(status_code=400, detail="Mot de passe incorrect")

            # Vérifie que le nouvel email n'est pas déjà utilisé
            existing = await repo.get_by_email(str(body.new_email))
            if existing and existing.id != u.id:
                raise HTTPException(status_code=409, detail="Cette adresse e-mail est déjà utilisée")

            u.email = str(body.new_email)
            await session.commit()
            return {"email": u.email}

    @router.patch("/password", status_code=status.HTTP_200_OK)
    async def change_password(
        body: ChangePasswordRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        async with db.session() as session:
            repo = UserRepository(session)
            u = await repo.get(user["sub"])
            if not u:
                raise HTTPException(status_code=404, detail="Utilisateur introuvable")
            if u.mfa_enabled:
                if not body.opt_code:
                    raise HTTPException(status_code=400, detail="Code OTP requis pour changer le mot de passe")

                mfa_service = MFAService(session)

                if not await mfa_service.verify_totp(user_id=u.id, code=body.opt_code):
                    raise HTTPException(status_code=400, detail="Code OTP incorrect")

            if not u.hashed_password or not get_pwd_context().verify(body.current_password, u.hashed_password):
                raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")

            try:
                _check_password_policy(body.new_password)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

            u.hashed_password = get_pwd_context().hash(body.new_password)
            await session.commit()

            # send see notification for user
            await call_plugin("XPulse", "xpulse.publish",{
                "channels": ["notification"],
                "user_id": u.id,
                "text": "Votre mot de passe a été modifié avec succès./nVous serez déconnecté de toute vos sessions ouvertes pour des raisons de sécurité.",
            })
            # Ne jamais ré-ouvrir `session` comme context manager une seconde fois
            # (elle est déjà dans le `async with db.session() as session:` englobant —
            # un second `async with session as ss:` risque de la fermer prématurément
            # avant que le commit ci-dessous ne persiste la révocation). On réutilise
            # directement `session` et on commit explicitement après, car
            # `revoke_all_for_user` ne fait qu'un `flush()`, jamais de commit.
            await Ss(
                session=session, events=XAuthEvents(bus=event_bus), token_service=token_service, cache=None
            ).invalidate_all_sessions(user_id=u.id)
            await session.commit()

            return {"ok": True}

    return router
