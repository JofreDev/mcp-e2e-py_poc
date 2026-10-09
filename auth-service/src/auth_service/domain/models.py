from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID


class ActorType(StrEnum):
    HUMAN = "human"
    AGENT = "agent"


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


@dataclass(slots=True)
class Principal:
    id: UUID
    actor_type: ActorType
    identifier: str
    password_hash: str
    is_active: bool
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class Authorization:
    roles: frozenset[str]
    permissions: frozenset[str]

    @property
    def is_admin(self) -> bool:
        return "admin" in self.roles


@dataclass(slots=True)
class StoredToken:
    jti: UUID
    principal_id: UUID
    family_id: UUID
    token_type: TokenType
    issued_at: int
    expires_at: int
    revoked_at: int | None = None
    replaced_by_jti: UUID | None = None


@dataclass(frozen=True, slots=True)
class TokenClaims:
    issuer: str
    audience: str
    subject: UUID
    jti: UUID
    family_id: UUID
    actor_type: ActorType
    token_type: TokenType
    issued_at: int
    expires_at: int
    admin: bool = False
    permissions: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class TokenPair:
    access_token: str
    refresh_token: str
    access_expires_at: int
    refresh_expires_at: int


@dataclass(frozen=True, slots=True)
class AuthenticatedPrincipal:
    principal: Principal
    authorization: Authorization
    token_jti: UUID
    token_family_id: UUID
    expires_at: int

    @property
    def expires_at_datetime(self) -> datetime:
        return datetime.fromtimestamp(self.expires_at, tz=UTC)
