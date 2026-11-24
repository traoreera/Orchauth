"""Un compte créé POUR quelqu'un, avec un mot de passe provisoire : qui peut le créer, ce qui est rendu, et surtout ce que le
mot de passe provisoire N'OUVRE PAS — aucune session tant que son titulaire n'a pas choisi le sien."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from src.models import Role, Tenant, User
from src.models.user import TenantMember
from src.services.auth.authentication import AuthenticationService
from src.services.auth.password import get_pwd_context
from src.services.iam import IamForbidden, IamInvalid, IamService, temporary_password
from src.services.password import PasswordService
from src.services.token import TokenService
from src.utils.db_upgrade import ADDED_COLUMNS


class Cache:
    def __init__(self):
        self.data = {}

    async def set(self, key, value, ttl=None):
        self.data[key] = value

    async def get(self, key):
        return self.data.get(key)

    async def delete(self, key):
        self.data.pop(key, None)


class Events:
    def __getattr__(self, name):
        async def nothing(**_):
            return None

        return nothing


@pytest.fixture
def tokens(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private, public = tmp_path / "private.pem", tmp_path / "public.pem"
    private.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    return TokenService(str(private), str(public))


@pytest.fixture
async def org(session):
    """Une organisation, sa propriétaire, un simple membre, et une seconde organisation."""
    session.add_all([
        Tenant(id="t1", name="Alpha", slug="alpha"), Tenant(id="t2", name="Beta", slug="beta"),
        User(id="owner", email="owner@x.test", hashed_password=get_pwd_context().hash("Owner-Passw0rd")),
        User(id="plain", email="plain@x.test"),
    ])
    await session.flush()
    session.add_all([TenantMember(user_id="owner", tenant_id="t1", is_owner=True), TenantMember(user_id="plain", tenant_id="t1")])
    await session.commit()
    return session


async def test_an_administrator_creates_an_account_with_a_temporary_password(org):
    made = await IamService(org).member_provision("t1", "owner", "  Fatou@Exemple.CI ")
    assert made["email"] == "fatou@exemple.ci" and made["must_change_password"] is True
    user = await org.get(User, made["user_id"])
    assert user.must_change_password is True and get_pwd_context().verify(made["temporary_password"], user.hashed_password)
    assert made["temporary_password"] not in user.hashed_password  # jamais en clair en base
    members = {m["email"] for m in await IamService(org).members("t1", "owner")}
    assert "fatou@exemple.ci" in members  # il est membre de CETTE organisation


async def test_a_temporary_password_passes_the_policy_and_is_never_the_same(org):
    drawn = {temporary_password() for _ in range(200)}
    assert len(drawn) == 200
    for p in drawn:
        assert len(p) >= 12 and any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p)


async def test_only_who_administers_the_organisation_creates_accounts(org):
    for actor in ("plain", "nobody", "", None):
        with pytest.raises(IamForbidden):
            await IamService(org).member_provision("t1", actor, "x@exemple.ci")
    with pytest.raises(IamForbidden):  # propriétaire d'Alpha, rien dans Beta
        await IamService(org).member_provision("t2", "owner", "x@exemple.ci")


async def test_an_existing_account_never_gets_a_password_this_way(org):
    """La porte ne sert qu'à CRÉER : sinon un administrateur poserait un mot de passe sur le compte d'un autre — un compte qui
    vaut pour toutes ses organisations."""
    before = (await org.get(User, "owner")).hashed_password
    for address in ("owner@x.test", "OWNER@x.test", "plain@x.test"):
        with pytest.raises(IamInvalid, match="existe déjà"):
            await IamService(org).member_provision("t1", "owner", address)
    assert (await org.get(User, "owner")).hashed_password == before


@pytest.mark.parametrize("address", ["", None, "pas-une-adresse", "a@b", "a b@c.fr", 12])
async def test_a_bad_address_is_refused(org, address):
    with pytest.raises(IamInvalid):
        await IamService(org).member_provision("t1", "owner", address)


async def test_a_role_of_another_organisation_is_refused(org):
    org.add(Role(id="r-beta", tenant_id="t2", name="r-beta"))
    await org.flush()
    with pytest.raises(ValueError):
        await IamService(org).member_provision("t1", "owner", "x@exemple.ci", "r-beta")


async def test_the_temporary_password_opens_no_session(org, tokens):
    """Le cœur de la règle : avec le mot de passe provisoire, la connexion ne rend NI jeton d'accès NI jeton de
    renouvellement, et n'écrit aucune session — seulement de quoi choisir un mot de passe."""
    from sqlalchemy import func, select

    from src.models.session import Session

    cache = Cache()
    made = await IamService(org).member_provision("t1", "owner", "fatou@exemple.ci")
    auth = AuthenticationService(org, tokens, Events(), cache=cache)
    for tenant in (None, "t1"):  # qu'il nomme son organisation ou non : aucune sortie de `login` n'y échappe
        out = await auth.login("fatou@exemple.ci", made["temporary_password"], tenant_id=tenant)
        assert out["access_token"] == "" and out["refresh_token"] == ""
        assert out["password_change_required"] is True and out["password_change_token"]
    assert (await org.execute(select(func.count()).select_from(Session).where(Session.user_id == made["user_id"]))).scalar() == 0

    with pytest.raises(ValueError):  # un mauvais mot de passe reste un mauvais mot de passe : pas de jeton de changement
        await auth.login("fatou@exemple.ci", "Mauvais-Passw0rd")


async def test_choosing_a_password_opens_the_account(org, tokens):
    cache = Cache()
    made = await IamService(org).member_provision("t1", "owner", "fatou@exemple.ci")
    auth = AuthenticationService(org, tokens, Events(), cache=cache)
    held = await auth.login("fatou@exemple.ci", made["temporary_password"])
    passwords = PasswordService(org, cache, Events())

    with pytest.raises(ValueError, match="différent"):  # « changer » pour le même : le provisoire resterait connu d'un tiers
        await passwords.reset_password(token=held["password_change_token"], new_password=made["temporary_password"])
    await passwords.reset_password(token=held["password_change_token"], new_password="Le-Mien-2026")
    assert (await org.get(User, made["user_id"])).must_change_password is False

    with pytest.raises(ValueError):  # le jeton ne sert qu'une fois
        await passwords.reset_password(token=held["password_change_token"], new_password="Encore-Un-2026")
    with pytest.raises(ValueError):  # le provisoire ne vaut plus rien
        await auth.login("fatou@exemple.ci", made["temporary_password"])
    out = await auth.login("fatou@exemple.ci", "Le-Mien-2026")
    assert out["access_token"] and out["tenant_id"] == "t1" and not out.get("password_change_required")


async def test_an_ordinary_account_logs_in_as_before(org, tokens):
    out = await AuthenticationService(org, tokens, Events(), cache=Cache()).login("owner@x.test", "Owner-Passw0rd")
    assert out["access_token"] and not out.get("password_change_required")


def test_an_existing_database_gains_the_column():
    assert ("xauth_users", "must_change_password", "BOOLEAN", None) in ADDED_COLUMNS


async def test_the_caller_may_supply_the_temporary_password(org, tokens):
    """Un hôte qui dérive le mot de passe de son service de clés le FOURNIT : il est pris tel quel, rendu, et reste provisoire —
    aucune session tant qu'il n'est pas changé. Un mot de passe faible ou trop court est refusé, rien n'est créé."""
    made = await IamService(org).member_provision("t1", "owner", "fatou@exemple.ci", None, "Derive-Par-Hote-42")
    assert made["temporary_password"] == "Derive-Par-Hote-42" and made["must_change_password"] is True
    out = await AuthenticationService(org, tokens, Events(), cache=Cache()).login("fatou@exemple.ci", "Derive-Par-Hote-42")
    assert out["access_token"] == "" and out["password_change_required"] is True

    for weak in ("court1A", "toutenminuscules123", "SANSCHIFFRESDUTOUT", 12345678901234, ""):
        with pytest.raises(IamInvalid):
            await IamService(org).member_provision("t1", "owner", "autre@exemple.ci", None, weak)
    assert "autre@exemple.ci" not in {m["email"] for m in await IamService(org).members("t1", "owner")}
