import httpx
from fastmcp import FastMCP
from fastmcp.dependencies import CurrentHeaders

from mcp_service.config import Settings
from mcp_service.services import (
    AuthenticationError,
    AuthorizationError,
    AuthServiceClient,
    FrankfurterClient,
    InputError,
    ProviderError,
    extract_bearer_token,
)

settings = Settings()
server = FastMCP(
    "Protected Currency Converter",
    instructions=(
        "Converts currencies only for authenticated agent identities with the fx:read permission."
    ),
)


@server.tool
async def convert_currency(
    amount: float,
    from_currency: str,
    to_currency: str,
    date: str | None = None,
    headers: dict[str, str] = CurrentHeaders(),  # noqa: B008
) -> dict[str, str]:
    """Convert a positive amount between ISO currency codes using Frankfurter rates."""
    token = extract_bearer_token(headers)
    timeout = httpx.Timeout(settings.request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as client:
        await AuthServiceClient(client, settings.auth_service_url).require_fx_read(token)
        return await FrankfurterClient(client).convert(amount, from_currency, to_currency, date)


def main() -> None:
    server.run(
        transport="http",
        host=settings.host,
        port=settings.port,
        path="/mcp",
        stateless_http=True,
        host_origin_protection=True,
        allowed_hosts=["127.0.0.1", "localhost"],
        allowed_origins=["http://127.0.0.1:8001", "http://localhost:8001"],
    )


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "InputError",
    "ProviderError",
    "main",
    "server",
]
