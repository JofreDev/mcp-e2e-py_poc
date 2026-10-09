import math
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

CURRENCY_CODE = re.compile(r"^[A-Z]{3}$")


class AuthenticationError(Exception):
    """The access token could not be validated."""


class AuthorizationError(Exception):
    """The authenticated identity does not have the required permission."""


class ProviderError(Exception):
    """Frankfurter did not provide a usable exchange rate."""


class InputError(Exception):
    """The tool arguments do not meet the public contract."""


class AuthServiceClient:
    def __init__(self, client: httpx.AsyncClient, base_url: str) -> None:
        self._client = client
        self._validate_url = f"{base_url.rstrip('/')}/api/v1/auth/validate"

    async def require_fx_read(self, token: str) -> None:
        try:
            response = await self._client.get(
                self._validate_url,
                headers={"Authorization": f"Bearer {token}"},
            )
        except httpx.HTTPError as error:
            raise AuthenticationError("Authentication service is unavailable") from error

        if response.status_code != httpx.codes.OK:
            raise AuthenticationError("Access token is invalid or no longer active")

        try:
            payload: dict[str, Any] = response.json()
            permissions = payload["permissions"]
        except (KeyError, TypeError, ValueError) as error:
            raise AuthenticationError(
                "Authentication service returned an invalid response"
            ) from error

        if not isinstance(permissions, list) or "fx:read" not in permissions:
            raise AuthorizationError("The authenticated identity requires the fx:read permission")


class FrankfurterClient:
    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def convert(
        self,
        amount: float,
        from_currency: str,
        to_currency: str,
        rate_date: str | None,
    ) -> dict[str, str]:
        source = validate_currency(from_currency, "from_currency")
        target = validate_currency(to_currency, "to_currency")
        requested_date = validate_date(rate_date)
        decimal_amount = validate_amount(amount)
        params = {"date": requested_date} if requested_date is not None else None

        try:
            response = await self._client.get(
                f"https://api.frankfurter.dev/v2/rate/{source.lower()}/{target.lower()}",
                params=params,
            )
        except httpx.HTTPError as error:
            raise ProviderError("Exchange-rate provider is unavailable") from error

        if response.status_code != httpx.codes.OK:
            raise ProviderError(
                "Exchange-rate provider could not resolve the requested currency pair"
            )

        try:
            payload: dict[str, Any] = response.json()
            rate = Decimal(str(payload["rate"]))
            effective_date = str(payload["date"])
        except (InvalidOperation, KeyError, TypeError, ValueError) as error:
            raise ProviderError("Exchange-rate provider returned an invalid response") from error

        converted_amount = decimal_amount * rate
        return {
            "amount": str(decimal_amount),
            "from_currency": source,
            "to_currency": target,
            "rate": str(rate),
            "converted_amount": str(converted_amount),
            "date": effective_date,
        }


def extract_bearer_token(headers: dict[str, str] | Any) -> str:
    authorization = headers.get("authorization") if headers is not None else None
    if not isinstance(authorization, str):
        raise AuthenticationError("Bearer access token is required")
    scheme, separator, token = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not separator or not token.strip():
        raise AuthenticationError("Bearer access token is required")
    return token.strip()


def validate_amount(amount: float) -> Decimal:
    if not math.isfinite(amount) or amount <= 0:
        raise InputError("amount must be a positive finite number")
    return Decimal(str(amount))


def validate_currency(value: str, field_name: str) -> str:
    normalized = value.upper()
    if CURRENCY_CODE.fullmatch(normalized) is None:
        raise InputError(f"{field_name} must be a three-letter ISO currency code")
    return normalized


def validate_date(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise InputError("date must use the YYYY-MM-DD format") from error
    if parsed.isoformat() != value:
        raise InputError("date must use the YYYY-MM-DD format")
    return value
