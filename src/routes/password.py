from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, field_validator
from xcore.kernel.api import AuthPayload, get_current_user

from ..services.email import AuthEmailService
from ..services.events import XAuthEvents
from ..services.password import PasswordService


# ── Schemas ───────────────────────────────────────────────────────────────────

class ForgotPasswordRequest(BaseModel):
    email: EmailStr


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str
    otp_code: str | None = None

    @field_validator("new_password")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Le mot de passe ne peut pas être vide.")
        return v


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str
    opt_code:str | None = None


class SetPasswordRequest(BaseModel):
    new_password: str

    @field_validator("new_password")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Le mot de passe ne peut pas être vide.")
        return v


# ── Router factory ────────────────────────────────────────────────────────────

def password_router(
    db: Any,
    cache: Any,
    email_service: AuthEmailService,
    events: XAuthEvents | None = None,
) -> APIRouter:
    router = APIRouter(prefix="/password", tags=["password"])

    def _svc(session) -> PasswordService:
        return PasswordService(session, cache, events)

    # ── Forgot / Reset ────────────────────────────────────────────────────────

    @router.post("/forgot", status_code=status.HTTP_202_ACCEPTED)
    async def forgot_password(body: ForgotPasswordRequest) -> Any:
        """
        Envoie un email de reset si l'adresse existe.
        Retourne toujours 202 pour éviter l'énumération des emails.
        """
        async with db.session() as session:
            svc = _svc(session)
            token = await svc.create_reset_token(body.email)

        if token:
            await email_service.password.reset(
                to=body.email,
                username=body.email,
                reset_token=token,
                expires_minutes=30,
            )

        return {"detail": "Si cet email existe, un lien de réinitialisation a été envoyé."}

    @router.post("/reset", status_code=status.HTTP_200_OK)
    async def reset_password(body: ResetPasswordRequest) -> Any:
        """Réinitialise le mot de passe via le token reçu par email."""
        async with db.session() as session:
            svc = _svc(session)
            try:
                email = await svc.reset_password(body.token, body.new_password)
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

        if email:
            email_service.password.queue(
                to=email,
                subject="Votre mot de passe a été modifié",
                body="Votre mot de passe a été réinitialisé avec succès.",
            )

        return {"detail": "Mot de passe réinitialisé avec succès."}

    # ── Set (comptes OAuth sans password) ─────────────────────────────────────

    @router.post("/set", status_code=status.HTTP_200_OK)
    async def set_password(
        body: SetPasswordRequest,
        user: AuthPayload = Depends(get_current_user),
    ) -> Any:
        """
        Définit un mot de passe pour les comptes créés via OAuth
        qui n'en ont pas encore.
        """
        async with db.session() as session:
            svc = _svc(session)
            try:
                await svc.set_password(
                    user_id=user["sub"],
                    new_password=body.new_password,
                )
                await session.commit()
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))

        return {"detail": "Mot de passe défini avec succès."}

    return router
