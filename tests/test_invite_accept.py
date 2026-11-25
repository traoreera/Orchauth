"""`POST /invites/accept` : l'identité de qui rejoint vient du JETON, jamais du corps.

`user_id` était OBLIGATOIRE dans le corps alors que la route ne s'en servait pas : le Desk, qui n'envoie que `{token}`, recevait
422 à chaque acceptation (mesuré sur un hôte réel). Il est facultatif ; présent, il doit être celui de la session.
"""

from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi import FastAPI
from xcore.kernel.api import get_current_user

from src.models import Invite, Tenant, TenantMember, User
from src.routes.invites import invites_router
from sqlalchemy import select


class Db:
    """Le service `db` d'xcore tel que la route l'emploie : `async with db.session()` — ici la session de test."""

    def __init__(self, session):
        self._s = session

    @asynccontextmanager
    async def session(self):
        yield self._s


@pytest.fixture
async def client(session):
    session.add_all([Tenant(id="t1", name="Alpha", slug="alpha"), User(id="u1", email="admin@x.test"),
                     User(id="u2", email="awa@x.test")])
    await session.flush()
    session.add(Invite(id="i1", tenant_id="t1", invited_by="u1", email="awa@x.test", token="tok-1",
                       expires_at=datetime.now(timezone.utc) + timedelta(hours=2)))
    await session.commit()
    app = FastAPI()
    app.include_router(invites_router(Db(session), email_service=None))
    app.dependency_overrides[get_current_user] = lambda: {"sub": "u2", "user": {"email": "awa@x.test"}}
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as c:
        yield c


async def member_of(session, user_id: str) -> list[str]:
    return [m.tenant_id for m in (await session.execute(select(TenantMember).where(TenantMember.user_id == user_id))).scalars()]


async def test_le_jeton_seul_suffit(client, session) -> None:
    r = await client.post("/invites/accept", json={"token": "tok-1"})
    assert r.status_code == 200, r.text
    assert r.json()["user_id"] == "u2" and await member_of(session, "u2") == ["t1"]


async def test_un_user_id_qui_est_celui_de_la_session_reste_accepte(client, session) -> None:
    r = await client.post("/invites/accept", json={"token": "tok-1", "user_id": "u2"})
    assert r.status_code == 200, r.text


async def test_on_n_accepte_pas_pour_un_autre(client, session) -> None:
    r = await client.post("/invites/accept", json={"token": "tok-1", "user_id": "u1"})
    assert r.status_code == 403
    assert await member_of(session, "u1") == [] and await member_of(session, "u2") == []  # rien n'a été fait
