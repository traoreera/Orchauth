from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base

if TYPE_CHECKING:
    from .user import User


class OAuthAccount(Base):
    __tablename__ = "xauth_oauth_accounts"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid4())
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("xauth_users.id", ondelete="CASCADE"), nullable=False
    )
    provider: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    provider_avatar: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(tz=timezone.utc))

    # Jetons d'accès aux API du provider (ex. Gmail/Calendar pour Google),
    # au-delà du simple login — chiffrés au repos (Fernet, voir
    # services/token_crypto.py), jamais stockés en clair : contrairement à
    # un refresh token de session xauth (révocable, scope limité à la
    # plateforme), ces jetons donnent un accès direct et durable au compte
    # Gmail/Calendar réel de l'utilisateur.
    access_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    refresh_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    # Scopes réellement accordés par l'utilisateur au consentement (peut être
    # un sous-ensemble de ceux demandés) — espace-séparés, tels que renvoyés
    # par le provider.
    granted_scopes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    user: Mapped["User"] = relationship("User", back_populates="oauth_accounts")

    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_uid"),
        Index("ix_xauth_oauth_user_id", "user_id"),
    )
