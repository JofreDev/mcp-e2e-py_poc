from datetime import UTC, datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from auth_service.application.auth_service import (
    AGENT_IDENTIFIER_MAX_LENGTH,
    AGENT_IDENTIFIER_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
)
from auth_service.domain.models import (
    ActorType,
    AuthenticatedPrincipal,
    Principal,
    TokenPair,
)


class StrictRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")


class HumanRegistrationRequest(StrictRequest):
    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class AgentRegistrationRequest(StrictRequest):
    username: str = Field(
        min_length=AGENT_IDENTIFIER_MIN_LENGTH,
        max_length=AGENT_IDENTIFIER_MAX_LENGTH,
    )
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)


class LoginRequest(StrictRequest):
    actor_type: ActorType
    identifier: str = Field(min_length=1, max_length=254)
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)


class RefreshRequest(StrictRequest):
    refresh_token: str = Field(min_length=1)


class LogoutRequest(StrictRequest):
    refresh_token: str = Field(min_length=1)


class PrincipalResponse(BaseModel):
    id: UUID
    actor_type: ActorType
    identifier: str
    is_active: bool
    created_at: datetime

    @classmethod
    def from_domain(cls, principal: Principal) -> PrincipalResponse:
        return cls(
            id=principal.id,
            actor_type=principal.actor_type,
            identifier=principal.identifier,
            is_active=principal.is_active,
            created_at=principal.created_at,
        )


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    access_expires_at: datetime
    refresh_expires_at: datetime

    @classmethod
    def from_domain(cls, pair: TokenPair) -> TokenResponse:
        return cls(
            access_token=pair.access_token,
            refresh_token=pair.refresh_token,
            access_expires_at=datetime.fromtimestamp(pair.access_expires_at, tz=UTC),
            refresh_expires_at=datetime.fromtimestamp(pair.refresh_expires_at, tz=UTC),
        )


class ValidationResponse(BaseModel):
    active: bool = True
    principal: PrincipalResponse
    admin: bool
    permissions: list[str]
    token_jti: UUID
    family_id: UUID
    expires_at: datetime

    @classmethod
    def from_domain(cls, authentication: AuthenticatedPrincipal) -> ValidationResponse:
        return cls(
            principal=PrincipalResponse.from_domain(authentication.principal),
            admin=authentication.authorization.is_admin,
            permissions=sorted(authentication.authorization.permissions),
            token_jti=authentication.token_jti,
            family_id=authentication.token_family_id,
            expires_at=authentication.expires_at_datetime,
        )


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail
