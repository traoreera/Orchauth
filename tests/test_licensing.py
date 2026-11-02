"""Les modules payants : un membre n'a les droits d'un module payant que si son organisation y est abonnée — valablement.

Chaque règle de `services/licensing.py` a ici le test qui échoue sans elle."""

from datetime import datetime, timedelta, timezone

import pytest

from src.models import Permission, Role, Tenant, TenantMember, User
from src.services import licensing
from src.services.licensing import LicenseService, filter_permissions
from src.services.rbac.permissions import PermissionService

PERMS = ["caisse:cash_sale:write", "caisse:cash_session:read", "stock:item:read", "accounts:account:read"]


@pytest.fixture(autouse=True)
def paid():
    licensing.configure(["caisse"])
    yield
    licensing.configure([])


async def member(session, tenant_name="acme"):
    tenant = Tenant(name=tenant_name, slug=tenant_name)
    user = User(email=f"alice@{tenant_name}.test")
    role = Role(name="caissier", tenant=tenant, permissions=[Permission(name=f"{p}", source_plugin=p.split(":")[0]) for p in PERMS]
                if tenant_name == "acme" else [])
    session.add_all([tenant, user, role])
    await session.flush()
    session.add(TenantMember(user_id=user.id, tenant_id=tenant.id, role_id=role.id))
    await session.flush()
    return user.id, tenant.id


async def perms(session, user_id, tenant_id):
    return await PermissionService(session).get_permissions_for_user(user_id, tenant_id)


async def test_without_subscription_the_paid_module_s_rights_are_removed(session):
    uid, tid = await member(session)
    assert await perms(session, uid, tid) == ["accounts:account:read", "stock:item:read"]


async def test_an_active_subscription_gives_them_back(session):
    uid, tid = await member(session)
    await LicenseService(session).set(tid, "caisse", "active", None, None, "admin")
    assert await perms(session, uid, tid) == sorted(PERMS)


@pytest.mark.parametrize("status, days, kept", [
    ("trial", 7, True),            # un essai vaut un abonnement tant qu'il court
    ("active", -1, False),          # échu : ne compte plus, quel que soit l'état
    ("suspended", None, False),     # suspendu : ne compte pas
])
async def test_validity_follows_status_and_end_date(session, status, days, kept):
    uid, tid = await member(session)
    until = datetime.now(tz=timezone.utc).replace(tzinfo=None) + timedelta(days=days) if days is not None else None
    await LicenseService(session).set(tid, "caisse", status, until, None, "admin")
    assert ("caisse:cash_sale:write" in await perms(session, uid, tid)) is kept


async def test_a_free_module_is_never_filtered_and_nothing_is_paid_by_default(session):
    uid, tid = await member(session)
    licensing.configure([])
    assert await perms(session, uid, tid) == sorted(PERMS)


async def test_the_subscription_of_one_organisation_does_not_open_another(session):
    uid, tid = await member(session)
    _, other = await member(session, "globex")
    await LicenseService(session).set(other, "caisse", "active", None, None, "admin")
    assert "caisse:cash_sale:write" not in await perms(session, uid, tid)


async def test_the_filter_applies_after_the_cache(session):
    """Le cache des droits garde la liste COMPLÈTE : un abonnement activé vaut dès la requête suivante, sans attendre son expiration."""

    class Cache:
        def __init__(self):
            self.data = {}

        async def get(self, key):
            return self.data.get(key)

        async def set(self, key, value, ex=None):
            self.data[key] = value

    cache = Cache()
    uid, tid = await member(session)
    assert "caisse:cash_sale:write" not in await PermissionService(session, cache=cache).get_permissions_for_user(uid, tid)
    assert cache.data  # la liste complète est en cache…
    assert "caisse:cash_sale:write" not in await PermissionService(session, cache=cache).get_permissions_for_user(uid, tid)  # …filtrée à la lecture
    await LicenseService(session).set(tid, "caisse", "active", None, None, "admin")
    assert "caisse:cash_sale:write" in await PermissionService(session, cache=cache).get_permissions_for_user(uid, tid)


async def test_an_unknown_status_is_refused(session):
    _, tid = await member(session)
    with pytest.raises(ValueError):
        await LicenseService(session).set(tid, "caisse", "paid", None, None, "admin")


def test_filter_is_by_namespace_only():
    assert filter_permissions(["caisse:x:read", "caissette:y:read"], frozenset({"caisse"}), set()) == ["caissette:y:read"]


def test_the_paid_list_comes_from_the_environment_first():
    assert licensing.parse_paid({"licensing": {"paid_modules": ["caisse"]}}, {}) == ["caisse"]
    assert licensing.parse_paid({"licensing": {"paid_modules": ["caisse"]}}, {"XAUTH_PAID_MODULES": "paie, caisse"}) == ["paie", "caisse"]
