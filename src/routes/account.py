from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from xcore.kernel.api import AuthPayload, get_current_user

from ..repositories.user import UserRepository
from ..services.auth.password import get_pwd_context


class ChangeEmailRequest(BaseModel):
    new_email: EmailStr
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


def account_router(db: Any) -> APIRouter:
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

            if not u.hashed_password or not get_pwd_context().verify(body.current_password, u.hashed_password):
                raise HTTPException(status_code=400, detail="Mot de passe actuel incorrect")

            u.hashed_password = get_pwd_context().hash(body.new_password)
            await session.commit()
            return {"ok": True}

    return router
