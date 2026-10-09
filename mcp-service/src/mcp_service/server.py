import httpx
from mcp.server import MCPServer
from mcp.server.mcpserver import Context

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
server = MCPServer(
    "Protected Currency Converter",
    instructions=(
        "Converts currencies only for authenticated agent identities with the fx:read permission."
    ),
)


@server.tool()
async def convert_currency(
    amount: float,
    from_currency: str,
    to_currency: str,
    ctx: Context,
    date: str | None = None,
) -> dict[str, str]:
    """Convert a positive amount between ISO currency codes using Frankfurter rates."""
    token = extract_bearer_token(ctx.headers)
    timeout = httpx.Timeout(settings.request_timeout_seconds)
    async with httpx.AsyncClient(timeout=timeout) as client:
        await AuthServiceClient(client, settings.auth_service_url).require_fx_read(token)
        return await FrankfurterClient(client).convert(amount, from_currency, to_currency, date)


def main() -> None:
    server.run(
        transport="streamable-http",
        host=settings.host,
        port=settings.port,
        streamable_http_path="/mcp",
    )


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "InputError",
    "ProviderError",
    "main",
    "server",
]
