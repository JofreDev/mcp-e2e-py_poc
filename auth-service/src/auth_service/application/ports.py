from collections.abc import Callable, Sequence
from datetime import datetime
from types import TracebackType
from typing import Protocol, Self
from uuid import UUID

from auth_service.domain.models import (
    ActorType,
    Authorization,
    Principal,
    StoredToken,
    TokenClaims,
    TokenType,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class PasswordHasher(Protocol):
    def hash(self, password: str) -> str: ...

    def verify(self, password: str, password_hash: str | None) -> bool: ...


class TokenCodec(Protocol):
    def encode(self, claims: TokenClaims) -> str: ...

    def decode(self, token: str, expected_type: TokenType) -> TokenClaims: ...


class PrincipalRepository(Protocol):
    async def get_by_identifier(
        self, actor_type: ActorType, identifier: str
    ) -> Principal | None: ...

    async def get_by_id(self, principal_id: UUID) -> Principal | None: ...

    async def add(self, principal: Principal) -> None: ...


class AuthorizationRepository(Protocol):
    async def get_for_principal(self, principal_id: UUID) -> Authorization: ...

    async def assign_role(self, principal_id: UUID, role_name: str) -> None: ...


class TokenRepository(Protocol):
    async def get(self, jti: UUID) -> StoredToken | None: ...

    async def add_many(self, tokens: Sequence[StoredToken]) -> None: ...

    async def revoke_if_active(self, jti: UUID, revoked_at: int, replaced_by_jti: UUID) -> bool: ...

    async def revoke_family(self, family_id: UUID, revoked_at: int) -> None: ...


class UnitOfWork(Protocol):
    principals: PrincipalRepository
    authorization: AuthorizationRepository
    tokens: TokenRepository

    async def __aenter__(self) -> Self: ...

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...

    async def commit(self) -> None: ...


UnitOfWorkFactory = Callable[[], UnitOfWork]
