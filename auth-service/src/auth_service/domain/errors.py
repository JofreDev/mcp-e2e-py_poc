class AuthError(Exception):
    code = "authentication_error"
    default_message = "Authentication operation failed"

    def __init__(self, message: str | None = None) -> None:
        self.message = message or self.default_message
        super().__init__(self.message)


class InvalidInputError(AuthError):
    code = "invalid_input"
    default_message = "The provided data is invalid"


class PrincipalAlreadyExistsError(AuthError):
    code = "principal_already_exists"
    default_message = "An identity with that identifier already exists"


class InvalidCredentialsError(AuthError):
    code = "invalid_credentials"
    default_message = "Invalid credentials"


class InactivePrincipalError(AuthError):
    code = "inactive_principal"
    default_message = "The identity is inactive"


class InvalidTokenError(AuthError):
    code = "invalid_token"
    default_message = "The token is invalid or expired"


class ForbiddenError(AuthError):
    code = "forbidden"
    default_message = "The identity does not have the required permission"
