"""L'abonnement d'une organisation à un module PAYANT (`caisse`, …) : une ligne par (organisation, module).

Un module payant est un espace de noms de droits (`caisse:*`, celui que son plugin déclare par `rbac.declare`). Sans abonnement
valide, xauth retire ces droits de ceux qu'il calcule pour un membre de l'organisation (`services/licensing.py`) : le module
disparaît du Desk et l'API le refuse, sans rien changer au plugin. Seul l'administrateur de la plateforme écrit ici (`license:manage`).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from sqlalchemy import DateTime, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base

STATUSES = ("active", "trial", "suspended")


class TenantModule(Base):
    __tablename__ = "xauth_tenant_modules"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("xauth_tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    # Fin de validité (UTC). Vide = sans fin. Passée, l'abonnement ne compte plus, quel que soit son état.
    valid_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    note: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(tz=timezone.utc))
    updated_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    __table_args__ = (UniqueConstraint("tenant_id", "module", name="ux_xauth_tenant_module"),)
