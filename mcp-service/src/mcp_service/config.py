from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="MCP_", extra="ignore")

    auth_service_url: str = "http://127.0.0.1:8000"
    request_timeout_seconds: float = Field(default=10.0, gt=0)
    host: str = "127.0.0.1"
    port: int = Field(default=8001, ge=1, le=65535)
