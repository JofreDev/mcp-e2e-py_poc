from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse

from auth_service.domain.errors import (
    AuthError,
    ForbiddenError,
    InactivePrincipalError,
    InvalidCredentialsError,
    InvalidInputError,
    InvalidTokenError,
    PrincipalAlreadyExistsError,
)


def register_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AuthError)
    async def handle_auth_error(_: Request, error: AuthError) -> JSONResponse:
        status_code = _status_code_for(error)
        headers = None
        if isinstance(error, (InvalidCredentialsError, InvalidTokenError)):
            headers = {"WWW-Authenticate": "Bearer"}
        return JSONResponse(
            status_code=status_code,
            headers=headers,
            content={
                "error": {
                    "code": error.code,
                    "message": error.message,
                }
            },
        )


def _status_code_for(error: AuthError) -> int:
    if isinstance(error, InvalidInputError):
        return status.HTTP_422_UNPROCESSABLE_CONTENT
    if isinstance(error, PrincipalAlreadyExistsError):
        return status.HTTP_409_CONFLICT
    if isinstance(error, (InvalidCredentialsError, InvalidTokenError)):
        return status.HTTP_401_UNAUTHORIZED
    if isinstance(error, (InactivePrincipalError, ForbiddenError)):
        return status.HTTP_403_FORBIDDEN
    return status.HTTP_400_BAD_REQUEST
