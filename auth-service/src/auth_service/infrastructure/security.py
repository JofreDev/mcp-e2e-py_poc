from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import jwt
from jwt import PyJWTError
from pwdlib import PasswordHash
from pwdlib.exceptions import UnknownHashError

from auth_service.application.ports import Clock
from auth_service.domain.errors import InvalidTokenError
from auth_service.domain.models import ActorType, TokenClaims, TokenType


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(tz=UTC)


class Argon2PasswordHasher:
    def __init__(self) -> None:
        self._password_hash = PasswordHash.recommended()
        self._dummy_hash = self._password_hash.hash("not-a-real-password")

    def hash(self, password: str) -> str:
        return self._password_hash.hash(password)

    def verify(self, password: str, password_hash: str | None) -> bool:
        candidate_hash = password_hash or self._dummy_hash
        try:
            matches = self._password_hash.verify(password, candidate_hash)
        except UnknownHashError:
            return False
        return matches and password_hash is not None


class JwtTokenCodec:
    def __init__(
        self,
        secret: str,
        algorithm: str,
        issuer: str,
        audience: str,
        clock: Clock,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._audience = audience
        self._clock = clock
        self._lifetimes = {
            TokenType.ACCESS: access_token_ttl_seconds,
            TokenType.REFRESH: refresh_token_ttl_seconds,
        }

    def encode(self, claims: TokenClaims) -> str:
        payload: dict[str, Any] = {
            "iss": claims.issuer,
            "aud": claims.audience,
            "sub": str(claims.subject),
            "jti": str(claims.jti),
            "family_id": str(claims.family_id),
            "actor_type": claims.actor_type.value,
            "token_type": claims.token_type.value,
            "iat": claims.issued_at,
            "exp": claims.expires_at,
        }
        if claims.token_type is TokenType.ACCESS:
            payload["admin"] = claims.admin
            payload["permissions"] = list(claims.permissions)
        return jwt.encode(payload, self._secret, algorithm=self._algorithm)

    def decode(self, token: str, expected_type: TokenType) -> TokenClaims:
        try:
            payload = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
                options={
                    "require": [
                        "iss",
                        "aud",
                        "sub",
                        "jti",
                        "family_id",
                        "actor_type",
                        "token_type",
                        "iat",
                        "exp",
                    ],
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
            token_type = TokenType(payload["token_type"])
            if token_type is not expected_type:
                raise InvalidTokenError("Unexpected token type")

            issued_at = self._integer_claim(payload, "iat")
            expires_at = self._integer_claim(payload, "exp")
            now = int(self._clock.now().astimezone(UTC).timestamp())
            if issued_at > now or expires_at <= now or expires_at <= issued_at:
                raise InvalidTokenError
            if expires_at - issued_at != self._lifetimes[token_type]:
                raise InvalidTokenError("Unexpected token lifetime")

            admin, permissions = self._authorization_claims(payload, token_type)
            return TokenClaims(
                issuer=str(payload["iss"]),
                audience=str(payload["aud"]),
                subject=UUID(str(payload["sub"])),
                jti=UUID(str(payload["jti"])),
                family_id=UUID(str(payload["family_id"])),
                actor_type=ActorType(payload["actor_type"]),
                token_type=token_type,
                issued_at=issued_at,
                expires_at=expires_at,
                admin=admin,
                permissions=permissions,
            )
        except InvalidTokenError:
            raise
        except (PyJWTError, KeyError, TypeError, ValueError) as error:
            raise InvalidTokenError from error

    @staticmethod
    def _integer_claim(payload: dict[str, Any], name: str) -> int:
        value = payload[name]
        if type(value) is not int:
            raise InvalidTokenError(f"Claim '{name}' must be an integer")
        return value

    @staticmethod
    def _authorization_claims(
        payload: dict[str, Any], token_type: TokenType
    ) -> tuple[bool, tuple[str, ...]]:
        if token_type is TokenType.REFRESH:
            if "admin" in payload or "permissions" in payload:
                raise InvalidTokenError("Refresh token contains authorization claims")
            return False, ()

        admin = payload.get("admin")
        permissions = payload.get("permissions")
        if type(admin) is not bool or not isinstance(permissions, list):
            raise InvalidTokenError("Access token authorization claims are invalid")
        if any(not isinstance(permission, str) or not permission for permission in permissions):
            raise InvalidTokenError("Access token permissions are invalid")
        if len(set(permissions)) != len(permissions):
            raise InvalidTokenError("Access token permissions contain duplicates")
        return admin, tuple(permissions)
