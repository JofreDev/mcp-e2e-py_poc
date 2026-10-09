from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from auth_service.domain.errors import InvalidTokenError
from auth_service.domain.models import ActorType, TokenClaims, TokenType
from auth_service.infrastructure.security import Argon2PasswordHasher, JwtTokenCodec


class FixedClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def now(self) -> datetime:
        return self.current


@pytest.fixture
def clock() -> FixedClock:
    return FixedClock(datetime(2026, 10, 6, 12, 0, tzinfo=UTC))


@pytest.fixture
def codec(clock: FixedClock) -> JwtTokenCodec:
    return JwtTokenCodec(
        secret="a-secure-test-secret-with-at-least-32-bytes",
        algorithm="HS256",
        issuer="auth-service",
        audience="mcp-api",
        clock=clock,
        access_token_ttl_seconds=3600,
        refresh_token_ttl_seconds=604800,
    )


def make_claims(clock: FixedClock, token_type: TokenType = TokenType.ACCESS) -> TokenClaims:
    issued_at = int(clock.now().timestamp())
    lifetime = 3600 if token_type is TokenType.ACCESS else 604800
    return TokenClaims(
        issuer="auth-service",
        audience="mcp-api",
        subject=uuid4(),
        jti=uuid4(),
        family_id=uuid4(),
        actor_type=ActorType.HUMAN,
        token_type=token_type,
        issued_at=issued_at,
        expires_at=issued_at + lifetime,
        admin=token_type is TokenType.ACCESS,
        permissions=("profile:read",) if token_type is TokenType.ACCESS else (),
    )


def test_access_token_round_trip_contains_authorization_claims(
    codec: JwtTokenCodec, clock: FixedClock
) -> None:
    claims = make_claims(clock)

    token = codec.encode(claims)
    decoded = codec.decode(token, TokenType.ACCESS)
    raw_payload = jwt.decode(token, options={"verify_signature": False})

    assert decoded == claims
    assert raw_payload["admin"] is True
    assert raw_payload["permissions"] == ["profile:read"]
    assert raw_payload["actor_type"] == "human"
    assert raw_payload["aud"] == "mcp-api"


def test_refresh_token_omits_authorization_claims(codec: JwtTokenCodec, clock: FixedClock) -> None:
    claims = make_claims(clock, TokenType.REFRESH)

    token = codec.encode(claims)
    payload = jwt.decode(token, options={"verify_signature": False})

    assert "admin" not in payload
    assert "permissions" not in payload
    assert codec.decode(token, TokenType.REFRESH) == claims


def test_token_is_valid_one_second_before_expiration(
    codec: JwtTokenCodec, clock: FixedClock
) -> None:
    claims = make_claims(clock)
    token = codec.encode(claims)
    clock.current = datetime.fromtimestamp(claims.expires_at - 1, tz=UTC)

    assert codec.decode(token, TokenType.ACCESS).jti == claims.jti


@pytest.mark.parametrize("seconds_after_expiration", [0, 1])
def test_token_is_invalid_at_or_after_expiration(
    codec: JwtTokenCodec,
    clock: FixedClock,
    seconds_after_expiration: int,
) -> None:
    claims = make_claims(clock)
    token = codec.encode(claims)
    clock.current = datetime.fromtimestamp(
        claims.expires_at + seconds_after_expiration,
        tz=UTC,
    )

    with pytest.raises(InvalidTokenError):
        codec.decode(token, TokenType.ACCESS)


def test_codec_rejects_wrong_token_type(codec: JwtTokenCodec, clock: FixedClock) -> None:
    token = codec.encode(make_claims(clock, TokenType.REFRESH))

    with pytest.raises(InvalidTokenError, match="Unexpected token type"):
        codec.decode(token, TokenType.ACCESS)


@pytest.mark.parametrize(
    ("secret", "issuer", "audience"),
    [
        ("another-secure-secret-with-at-least-32-bytes", "auth-service", "mcp-api"),
        ("a-secure-test-secret-with-at-least-32-bytes", "other-service", "mcp-api"),
        ("a-secure-test-secret-with-at-least-32-bytes", "auth-service", "other-api"),
    ],
)
def test_codec_rejects_invalid_signature_issuer_or_audience(
    codec: JwtTokenCodec,
    clock: FixedClock,
    secret: str,
    issuer: str,
    audience: str,
) -> None:
    claims = make_claims(clock)
    payload = {
        "iss": issuer,
        "aud": audience,
        "sub": str(claims.subject),
        "jti": str(claims.jti),
        "family_id": str(claims.family_id),
        "actor_type": "human",
        "token_type": "access",
        "iat": claims.issued_at,
        "exp": claims.expires_at,
        "admin": False,
        "permissions": [],
    }
    token = jwt.encode(payload, secret, algorithm="HS256")

    with pytest.raises(InvalidTokenError):
        codec.decode(token, TokenType.ACCESS)


def test_codec_rejects_token_issued_in_future(codec: JwtTokenCodec, clock: FixedClock) -> None:
    claims = make_claims(clock)
    future_claims = TokenClaims(
        issuer=claims.issuer,
        audience=claims.audience,
        subject=claims.subject,
        jti=claims.jti,
        family_id=claims.family_id,
        actor_type=claims.actor_type,
        token_type=claims.token_type,
        issued_at=claims.issued_at + 1,
        expires_at=claims.expires_at + 1,
        permissions=claims.permissions,
    )

    with pytest.raises(InvalidTokenError):
        codec.decode(codec.encode(future_claims), TokenType.ACCESS)


def test_codec_rejects_unexpected_lifetime(codec: JwtTokenCodec, clock: FixedClock) -> None:
    claims = make_claims(clock)
    invalid_claims = TokenClaims(
        issuer=claims.issuer,
        audience=claims.audience,
        subject=claims.subject,
        jti=claims.jti,
        family_id=claims.family_id,
        actor_type=claims.actor_type,
        token_type=claims.token_type,
        issued_at=claims.issued_at,
        expires_at=claims.expires_at + 1,
        permissions=claims.permissions,
    )

    with pytest.raises(InvalidTokenError, match="Unexpected token lifetime"):
        codec.decode(codec.encode(invalid_claims), TokenType.ACCESS)


def test_password_hasher_accepts_correct_password_and_rejects_others() -> None:
    hasher = Argon2PasswordHasher()
    password_hash = hasher.hash("correct-horse")

    assert hasher.verify("correct-horse", password_hash)
    assert not hasher.verify("wrong-horse", password_hash)
    assert not hasher.verify("correct-horse", None)
    assert not hasher.verify("correct-horse", "not-a-supported-hash")


def test_fixed_clock_can_move_across_boundary(clock: FixedClock) -> None:
    original = clock.now()
    clock.current += timedelta(seconds=1)

    assert clock.now() == original + timedelta(seconds=1)
