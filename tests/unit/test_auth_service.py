from collections.abc import Sequence
from datetime import UTC, datetime
from types import TracebackType
from typing import ClassVar
from uuid import UUID

import pytest

from auth_service.application.auth_service import AuthService
from auth_service.domain.errors import (
    InactivePrincipalError,
    InvalidCredentialsError,
    InvalidInputError,
    InvalidTokenError,
    PrincipalAlreadyExistsError,
)
from auth_service.domain.models import (
    ActorType,
    Authorization,
    Principal,
    StoredToken,
    TokenClaims,
    TokenType,
)


class FixedClock:
    def __init__(self) -> None:
        self.current = datetime(2026, 10, 6, 12, 0, tzinfo=UTC)

    def now(self) -> datetime:
        return self.current


class FakePasswordHasher:
    def __init__(self) -> None:
        self.verified_missing_hash = False

    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify(self, password: str, password_hash: str | None) -> bool:
        if password_hash is None:
            self.verified_missing_hash = True
            return False
        return password_hash == f"hashed:{password}"


class FakeTokenCodec:
    def __init__(self) -> None:
        self.tokens: dict[str, TokenClaims] = {}

    def encode(self, claims: TokenClaims) -> str:
        token = f"token:{claims.jti}"
        self.tokens[token] = claims
        return token

    def decode(self, token: str, expected_type: TokenType) -> TokenClaims:
        claims = self.tokens.get(token)
        if claims is None or claims.token_type is not expected_type:
            raise InvalidTokenError
        return claims


class FakeState:
    def __init__(self) -> None:
        self.principals: dict[UUID, Principal] = {}
        self.authorizations: dict[UUID, Authorization] = {}
        self.tokens: dict[UUID, StoredToken] = {}


class FakePrincipalRepository:
    def __init__(self, state: FakeState) -> None:
        self.state = state

    async def get_by_identifier(self, actor_type: ActorType, identifier: str) -> Principal | None:
        return next(
            (
                principal
                for principal in self.state.principals.values()
                if principal.actor_type is actor_type and principal.identifier == identifier
            ),
            None,
        )

    async def get_by_id(self, principal_id: UUID) -> Principal | None:
        return self.state.principals.get(principal_id)

    async def add(self, principal: Principal) -> None:
        self.state.principals[principal.id] = principal


class FakeAuthorizationRepository:
    ROLE_PERMISSIONS: ClassVar[dict[str, frozenset[str]]] = {
        "user": frozenset({"profile:read"}),
        "agent": frozenset({"profile:read"}),
        "admin": frozenset({"users:read", "profile:read"}),
    }

    def __init__(self, state: FakeState) -> None:
        self.state = state

    async def get_for_principal(self, principal_id: UUID) -> Authorization:
        return self.state.authorizations.get(
            principal_id,
            Authorization(roles=frozenset(), permissions=frozenset()),
        )

    async def assign_role(self, principal_id: UUID, role_name: str) -> None:
        current = await self.get_for_principal(principal_id)
        self.state.authorizations[principal_id] = Authorization(
            roles=current.roles | {role_name},
            permissions=current.permissions | self.ROLE_PERMISSIONS[role_name],
        )


class FakeTokenRepository:
    def __init__(self, state: FakeState) -> None:
        self.state = state

    async def get(self, jti: UUID) -> StoredToken | None:
        return self.state.tokens.get(jti)

    async def add_many(self, tokens: Sequence[StoredToken]) -> None:
        self.state.tokens.update({token.jti: token for token in tokens})

    async def revoke_if_active(self, jti: UUID, revoked_at: int, replaced_by_jti: UUID) -> bool:
        token = self.state.tokens[jti]
        if token.revoked_at is not None:
            return False
        token.revoked_at = revoked_at
        token.replaced_by_jti = replaced_by_jti
        return True

    async def revoke_family(self, family_id: UUID, revoked_at: int) -> None:
        for token in self.state.tokens.values():
            if token.family_id == family_id and token.revoked_at is None:
                token.revoked_at = revoked_at


class FakeUnitOfWork:
    def __init__(self, state: FakeState) -> None:
        self.principals = FakePrincipalRepository(state)
        self.authorization = FakeAuthorizationRepository(state)
        self.tokens = FakeTokenRepository(state)
        self.committed = False

    async def __aenter__(self) -> FakeUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        return None

    async def commit(self) -> None:
        self.committed = True


@pytest.fixture
def service_components() -> tuple[
    AuthService,
    FakeState,
    FakePasswordHasher,
    FakeTokenCodec,
]:
    state = FakeState()
    hasher = FakePasswordHasher()
    codec = FakeTokenCodec()
    clock = FixedClock()
    service = AuthService(
        uow_factory=lambda: FakeUnitOfWork(state),
        password_hasher=hasher,
        token_codec=codec,
        clock=clock,
        issuer="auth-service",
        audience="mcp-api",
        access_token_ttl_seconds=3600,
        refresh_token_ttl_seconds=604800,
    )
    return service, state, hasher, codec


@pytest.mark.parametrize("length", [8, 128])
def test_password_boundary_values_are_accepted(length: int) -> None:
    AuthService.validate_password("x" * length)


@pytest.mark.parametrize("length", [7, 129])
def test_password_outside_boundaries_is_rejected(length: int) -> None:
    with pytest.raises(InvalidInputError):
        AuthService.validate_password("x" * length)


@pytest.mark.parametrize("length", [3, 64])
def test_agent_username_boundary_values_are_accepted(length: int) -> None:
    assert len(AuthService.normalize_identifier(ActorType.AGENT, "a" * length)) == length


@pytest.mark.parametrize("username", ["aa", "a" * 65, "-agent", "agent-"])
def test_invalid_agent_username_is_rejected(username: str) -> None:
    with pytest.raises(InvalidInputError):
        AuthService.normalize_identifier(ActorType.AGENT, username)


@pytest.mark.asyncio
async def test_register_human_normalizes_email_and_assigns_user_role(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, state, _, _ = service_components

    principal = await service.register_human(" Person@Example.COM ", "password")

    assert principal.identifier == "person@example.com"
    assert principal.password_hash == "hashed:password"
    assert state.authorizations[principal.id].roles == {"user"}


@pytest.mark.asyncio
async def test_duplicate_identity_is_rejected(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, _, _, _ = service_components
    await service.register_agent("report-agent", "password")

    with pytest.raises(PrincipalAlreadyExistsError):
        await service.register_agent("REPORT-AGENT", "password")


@pytest.mark.asyncio
async def test_login_returns_tokens_with_current_authorization(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, _, _, codec = service_components
    principal = await service.register_human("person@example.com", "password")

    pair = await service.login(ActorType.HUMAN, principal.identifier, "password")
    access_claims = codec.tokens[pair.access_token]
    refresh_claims = codec.tokens[pair.refresh_token]

    assert access_claims.permissions == ("profile:read",)
    assert access_claims.admin is False
    assert refresh_claims.permissions == ()
    assert access_claims.family_id == refresh_claims.family_id


@pytest.mark.asyncio
async def test_unknown_identity_uses_dummy_password_verification(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, _, hasher, _ = service_components

    with pytest.raises(InvalidCredentialsError):
        await service.login(ActorType.HUMAN, "missing@example.com", "password")

    assert hasher.verified_missing_hash


@pytest.mark.asyncio
async def test_wrong_password_is_rejected(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, _, _, _ = service_components
    await service.register_human("person@example.com", "password")

    with pytest.raises(InvalidCredentialsError):
        await service.login(ActorType.HUMAN, "person@example.com", "incorrect")


@pytest.mark.asyncio
async def test_inactive_identity_cannot_login(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, _, _, _ = service_components
    principal = await service.register_human("inactive@example.com", "password")
    principal.is_active = False

    with pytest.raises(InactivePrincipalError):
        await service.login(ActorType.HUMAN, principal.identifier, "password")


@pytest.mark.asyncio
async def test_identity_deactivated_after_login_cannot_validate_token(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, _, _, _ = service_components
    principal = await service.register_human("deactivated@example.com", "password")
    pair = await service.login(ActorType.HUMAN, principal.identifier, "password")
    principal.is_active = False

    with pytest.raises(InactivePrincipalError):
        await service.validate_access_token(pair.access_token)


@pytest.mark.asyncio
async def test_refresh_rotates_token_and_reuse_revokes_family(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, state, _, codec = service_components
    await service.register_human("person@example.com", "password")
    original_pair = await service.login(ActorType.HUMAN, "person@example.com", "password")

    rotated_pair = await service.refresh(original_pair.refresh_token)
    original_claims = codec.tokens[original_pair.refresh_token]
    rotated_access_claims = codec.tokens[rotated_pair.access_token]
    assert state.tokens[original_claims.jti].revoked_at is not None

    with pytest.raises(InvalidTokenError, match="reuse"):
        await service.refresh(original_pair.refresh_token)

    assert state.tokens[rotated_access_claims.jti].revoked_at is not None


@pytest.mark.asyncio
async def test_logout_revokes_access_and_refresh_tokens(
    service_components: tuple[AuthService, FakeState, FakePasswordHasher, FakeTokenCodec],
) -> None:
    service, state, _, codec = service_components
    await service.register_agent("report-agent", "password")
    pair = await service.login(ActorType.AGENT, "report-agent", "password")

    await service.logout(pair.refresh_token)

    family_id = codec.tokens[pair.refresh_token].family_id
    assert all(
        token.revoked_at is not None
        for token in state.tokens.values()
        if token.family_id == family_id
    )
    with pytest.raises(InvalidTokenError):
        await service.validate_access_token(pair.access_token)
