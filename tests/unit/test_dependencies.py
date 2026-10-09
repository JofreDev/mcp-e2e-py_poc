from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.security import HTTPAuthorizationCredentials

from auth_service.api.dependencies import get_bearer_token, require_permissions
from auth_service.domain.errors import ForbiddenError, InvalidTokenError
from auth_service.domain.models import (
    ActorType,
    AuthenticatedPrincipal,
    Authorization,
    Principal,
)


def authentication_with_permissions(*permissions: str) -> AuthenticatedPrincipal:
    principal_id = uuid4()
    principal = Principal(
        id=principal_id,
        actor_type=ActorType.HUMAN,
        identifier="person@example.com",
        password_hash="unused",
        is_active=True,
        created_at=datetime.now(tz=UTC),
        updated_at=datetime.now(tz=UTC),
    )
    return AuthenticatedPrincipal(
        principal=principal,
        authorization=Authorization(
            roles=frozenset({"user"}),
            permissions=frozenset(permissions),
        ),
        token_jti=uuid4(),
        token_family_id=uuid4(),
        expires_at=2_000_000_000,
    )


@pytest.mark.asyncio
async def test_bearer_dependency_returns_credentials() -> None:
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials="token")

    assert await get_bearer_token(credentials) == "token"


@pytest.mark.asyncio
async def test_bearer_dependency_rejects_missing_credentials() -> None:
    with pytest.raises(InvalidTokenError):
        await get_bearer_token(None)


@pytest.mark.asyncio
async def test_permission_dependency_allows_all_required_permissions() -> None:
    authentication = authentication_with_permissions("users:read", "users:update")
    dependency = require_permissions("users:read")

    assert await dependency(authentication=authentication) is authentication


@pytest.mark.asyncio
async def test_permission_dependency_denies_missing_permission() -> None:
    authentication = authentication_with_permissions("profile:read")
    dependency = require_permissions("users:read")

    with pytest.raises(ForbiddenError):
        await dependency(authentication=authentication)
