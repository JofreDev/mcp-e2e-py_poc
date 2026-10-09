from collections.abc import Awaitable, Callable
from typing import Annotated, cast

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from auth_service.application.auth_service import AuthService
from auth_service.domain.errors import ForbiddenError, InvalidTokenError
from auth_service.domain.models import AuthenticatedPrincipal

bearer_scheme = HTTPBearer(auto_error=False)


def get_auth_service(request: Request) -> AuthService:
    return cast(AuthService, request.app.state.auth_service)


async def get_bearer_token(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(bearer_scheme),
    ],
) -> str:
    if credentials is None or credentials.scheme.casefold() != "bearer":
        raise InvalidTokenError("Bearer token is required")
    return credentials.credentials


async def get_current_principal(
    token: Annotated[str, Depends(get_bearer_token)],
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthenticatedPrincipal:
    return await auth_service.validate_access_token(token)


def require_permissions(
    *required_permissions: str,
) -> Callable[..., Awaitable[AuthenticatedPrincipal]]:
    async def permission_dependency(
        authentication: Annotated[
            AuthenticatedPrincipal,
            Depends(get_current_principal),
        ],
    ) -> AuthenticatedPrincipal:
        if not set(required_permissions).issubset(authentication.authorization.permissions):
            raise ForbiddenError
        return authentication

    return permission_dependency
