import httpx
import pytest

from mcp_service.services import (
    AuthenticationError,
    AuthorizationError,
    AuthServiceClient,
    FrankfurterClient,
    InputError,
    ProviderError,
    extract_bearer_token,
)


@pytest.mark.asyncio
async def test_authorized_agent_can_convert_currency() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "auth.example":
            assert request.headers["Authorization"] == "Bearer access-token"
            return httpx.Response(200, json={"permissions": ["fx:read", "profile:read"]})
        assert request.url == httpx.URL(
            "https://api.frankfurter.dev/v2/rate/eur/usd?date=2024-05-15"
        )
        return httpx.Response(200, json={"date": "2024-05-15", "rate": 1.08})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await AuthServiceClient(client, "https://auth.example").require_fx_read("access-token")
        result = await FrankfurterClient(client).convert(10, "eur", "usd", "2024-05-15")

    assert result == {
        "amount": "10",
        "from_currency": "EUR",
        "to_currency": "USD",
        "rate": "1.08",
        "converted_amount": "10.80",
        "date": "2024-05-15",
    }


@pytest.mark.asyncio
async def test_invalid_access_token_is_rejected() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(401))
    ) as client:
        with pytest.raises(AuthenticationError, match="invalid"):
            await AuthServiceClient(client, "https://auth.example").require_fx_read("expired")


@pytest.mark.asyncio
async def test_missing_fx_read_permission_is_rejected() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"permissions": []}))
    ) as client:
        with pytest.raises(AuthorizationError, match="fx:read"):
            await AuthServiceClient(client, "https://auth.example").require_fx_read("valid-token")


@pytest.mark.asyncio
async def test_provider_error_is_reported() -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: httpx.Response(422))
    ) as client:
        with pytest.raises(ProviderError, match="could not resolve"):
            await FrankfurterClient(client).convert(1, "EUR", "ZZZ", None)


@pytest.mark.parametrize("amount", [0, -1, float("inf")])
@pytest.mark.asyncio
async def test_invalid_amount_is_rejected_before_provider_call(amount: float) -> None:
    async with httpx.AsyncClient(
        transport=httpx.MockTransport(lambda _: pytest.fail("provider must not be called"))
    ) as client:
        with pytest.raises(InputError, match="positive finite"):
            await FrankfurterClient(client).convert(amount, "EUR", "USD", None)


def test_missing_bearer_header_is_rejected() -> None:
    with pytest.raises(AuthenticationError, match="required"):
        extract_bearer_token({})
