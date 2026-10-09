from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from auth_service.api.dependencies import get_auth_service, get_current_principal
from auth_service.api.schemas import (
    AgentRegistrationRequest,
    HumanRegistrationRequest,
    LoginRequest,
    LogoutRequest,
    PrincipalResponse,
    RefreshRequest,
    TokenResponse,
    ValidationResponse,
)
from auth_service.application.auth_service import AuthService
from auth_service.domain.models import AuthenticatedPrincipal

router = APIRouter(prefix="/auth", tags=["authentication"])


@router.post(
    "/humans/register",
    response_model=PrincipalResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_human(
    request: HumanRegistrationRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> PrincipalResponse:
    principal = await auth_service.register_human(str(request.email), request.password)
    return PrincipalResponse.from_domain(principal)


@router.post(
    "/agents/register",
    response_model=PrincipalResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register_agent(
    request: AgentRegistrationRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> PrincipalResponse:
    principal = await auth_service.register_agent(request.username, request.password)
    return PrincipalResponse.from_domain(principal)


@router.post("/login", response_model=TokenResponse)
async def login(
    request: LoginRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    pair = await auth_service.login(
        request.actor_type,
        request.identifier,
        request.password,
    )
    return TokenResponse.from_domain(pair)


@router.post("/refresh", response_model=TokenResponse)
async def refresh(
    request: RefreshRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> TokenResponse:
    pair = await auth_service.refresh(request.refresh_token)
    return TokenResponse.from_domain(pair)


@router.get("/validate", response_model=ValidationResponse)
async def validate_token(
    authentication: Annotated[
        AuthenticatedPrincipal,
        Depends(get_current_principal),
    ],
) -> ValidationResponse:
    return ValidationResponse.from_domain(authentication)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: LogoutRequest,
    auth_service: Annotated[AuthService, Depends(get_auth_service)],
) -> Response:
    await auth_service.logout(request.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
