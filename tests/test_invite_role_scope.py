from datetime import datetime, timedelta, timezone

import pytest

from src.models import Invite, Role, Tenant, User
from src.services.invite import InviteService


async def test_accept_invite_rejects_cross_tenant_role(session):
    tenant_a = Tenant(id="t1", name="Alpha", slug="alpha")
    tenant_b = Tenant(id="t2", name="Beta", slug="beta")
    inviter = User(id="u1", email="inviter@x.test")
    invitee = User(id="u2", email="invitee@x.test")
    foreign_role = Role(id="r-foreign", tenant_id="t2", name="r-foreign")

    session.add_all([tenant_a, tenant_b, inviter, invitee, foreign_role])
    await session.flush()

    invite = Invite(
        id="invite-1",
        tenant_id="t1",
        invited_by="u1",
        email="invitee@x.test",
        token="token-123",
        role_id="r-foreign",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
    )
    session.add(invite)
    await session.commit()

    with pytest.raises(ValueError, match="n'appartient pas à ce tenant"):
        await InviteService(session).accept_invite("token-123", "u2")
