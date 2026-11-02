"""Les routes /licenses : qui lit, qui écrit, ce qui est refusé. L'authentification est un faux backend (jeton = nom d'utilisateur)."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from xcore.kernel.api.auth import register_auth_backend

from src.models import Base, Tenant, TenantMember, User
from src.routes.licenses import licenses_router
from src.services import licensing

USERS = {
    "boss": {"sub": "boss", "permissions": ["license:manage"]},   # l'administrateur de la plateforme
    "alice": {"sub": "alice", "permissions": []},                 # membre de l'organisation
    "eve": {"sub": "eve", "permissions": []},                     # étrangère à l'organisation
}


class Backend:
    async def extract_token(self, request):
        auth = request.headers.get("authorization", "")
        return auth.removeprefix("Bearer ") or None

    async def decode_token(self, token):
        return USERS.get(token)

    async def has_permission(self, payload, permission):
        return permission in payload.get("permissions", [])


class Db:
    def __init__(self, maker):
        self._maker = maker

    def session(self):
        return self._maker()


@pytest.fixture
async def client():
    licensing.configure(["caisse"])
    register_auth_backend(Backend())
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as s:
        s.add_all([Tenant(id="t1", name="Acme", slug="acme"), User(id="alice", email="a@x.test"), User(id="eve", email="e@x.test")])
        await s.flush()
        s.add(TenantMember(user_id="alice", tenant_id="t1"))
        await s.commit()
    app = FastAPI()
    app.include_router(licenses_router(Db(maker)))
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        yield c
    licensing.configure([])
    await engine.dispose()


def as_(user):
    return {"Authorization": f"Bearer {user}"}


async def test_the_platform_admin_subscribes_and_the_member_reads_it(client):
    r = await client.put("/licenses/tenants/t1/caisse", json={"status": "active", "valid_until": "2099-01-01T00:00:00Z"}, headers=as_("boss"))
    assert r.status_code == 200 and r.json()["valid"] is True
    r = await client.get("/licenses/tenants/t1", headers=as_("alice"))
    assert r.json()["modules"] == [{**r.json()["modules"][0], "module": "caisse", "status": "active", "valid": True}]
    assert (await client.get("/licenses/catalog", headers=as_("alice"))).json() == {"paid_modules": ["caisse"]}


@pytest.mark.parametrize("user, path, body, code", [
    ("alice", "/licenses/tenants/t1/caisse", {"status": "active"}, 403),   # un membre ne s'abonne pas lui-même
    ("boss", "/licenses/tenants/t1/stock", {"status": "active"}, 422),     # un module gratuit n'a pas d'abonnement
    ("boss", "/licenses/tenants/t1/caisse", {"status": "paid"}, 422),      # état inconnu
    ("boss", "/licenses/tenants/nope/caisse", {"status": "active"}, 404),  # organisation inconnue
])
async def test_writes_are_refused_when_they_should_be(client, user, path, body, code):
    assert (await client.put(path, json=body, headers=as_(user))).status_code == code


async def test_a_stranger_cannot_read_an_organisation_s_subscriptions(client):
    assert (await client.get("/licenses/tenants/t1", headers=as_("eve"))).status_code == 403


async def test_removing_a_subscription(client):
    await client.put("/licenses/tenants/t1/caisse", json={"status": "trial"}, headers=as_("boss"))
    assert (await client.delete("/licenses/tenants/t1/caisse", headers=as_("boss"))).status_code == 204
    assert (await client.delete("/licenses/tenants/t1/caisse", headers=as_("boss"))).status_code == 404
