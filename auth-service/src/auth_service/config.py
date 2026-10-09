from typing import Self

from pydantic import EmailStr, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="AUTH_",
        extra="ignore",
    )

    app_name: str = "Authentication Service"
    database_url: str = "sqlite+aiosqlite:///./auth.db"
    auto_create_schema: bool = False

    jwt_secret: SecretStr
    jwt_algorithm: str = "HS256"
    jwt_issuer: str = "auth-service"
    jwt_audience: str = "mcp-api"
    access_token_ttl_seconds: int = 60 * 60
    refresh_token_ttl_seconds: int = 7 * 24 * 60 * 60

    bootstrap_admin_email: EmailStr | None = None
    bootstrap_admin_password: SecretStr | None = None

    @model_validator(mode="after")
    def validate_security_settings(self) -> Self:
        if self.jwt_algorithm != "HS256":
            raise ValueError("This service currently supports only HS256")
        if len(self.jwt_secret.get_secret_value().encode()) < 32:
            raise ValueError("AUTH_JWT_SECRET must contain at least 32 bytes")
        if self.access_token_ttl_seconds <= 0 or self.refresh_token_ttl_seconds <= 0:
            raise ValueError("Token lifetimes must be positive")

        email_set = self.bootstrap_admin_email is not None
        password_set = self.bootstrap_admin_password is not None
        if email_set != password_set:
            raise ValueError("Both bootstrap administrator variables must be configured")
        if self.bootstrap_admin_password is not None:
            password_length = len(self.bootstrap_admin_password.get_secret_value())
            if not 8 <= password_length <= 128:
                raise ValueError("Bootstrap administrator password must have 8 to 128 characters")
        return self
