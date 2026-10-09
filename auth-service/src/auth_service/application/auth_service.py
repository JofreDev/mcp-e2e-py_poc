import re
from datetime import UTC
from uuid import UUID, uuid4

from auth_service.application.ports import (
    Clock,
    PasswordHasher,
    TokenCodec,
    UnitOfWorkFactory,
)
from auth_service.domain.errors import (
    InactivePrincipalError,
    InvalidCredentialsError,
    InvalidInputError,
    InvalidTokenError,
    PrincipalAlreadyExistsError,
)
from auth_service.domain.models import (
    ActorType,
    AuthenticatedPrincipal,
    Authorization,
    Principal,
    StoredToken,
    TokenClaims,
    TokenPair,
    TokenType,
)

PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128
HUMAN_IDENTIFIER_MAX_LENGTH = 254
AGENT_IDENTIFIER_MIN_LENGTH = 3
AGENT_IDENTIFIER_MAX_LENGTH = 64
AGENT_IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$")


class AuthService:
    def __init__(
        self,
        uow_factory: UnitOfWorkFactory,
        password_hasher: PasswordHasher,
        token_codec: TokenCodec,
        clock: Clock,
        issuer: str,
        audience: str,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        self._uow_factory = uow_factory
        self._password_hasher = password_hasher
        self._token_codec = token_codec
        self._clock = clock
        self._issuer = issuer
        self._audience = audience
        self._access_ttl = access_token_ttl_seconds
        self._refresh_ttl = refresh_token_ttl_seconds

    async def register_human(self, email: str, password: str) -> Principal:
        identifier = self.normalize_identifier(ActorType.HUMAN, email)
        return await self._register(ActorType.HUMAN, identifier, password, "user")

    async def register_agent(self, username: str, password: str) -> Principal:
        identifier = self.normalize_identifier(ActorType.AGENT, username)
        return await self._register(ActorType.AGENT, identifier, password, "agent")

    async def _register(
        self, actor_type: ActorType, identifier: str, password: str, role: str
    ) -> Principal:
        self.validate_password(password)
        async with self._uow_factory() as uow:
            if await uow.principals.get_by_identifier(actor_type, identifier) is not None:
                raise PrincipalAlreadyExistsError

            now = self._clock.now().astimezone(UTC)
            principal = Principal(
                id=uuid4(),
                actor_type=actor_type,
                identifier=identifier,
                password_hash=self._password_hasher.hash(password),
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            await uow.principals.add(principal)
            await uow.authorization.assign_role(principal.id, role)
            await uow.commit()
            return principal

    async def login(self, actor_type: ActorType, identifier: str, password: str) -> TokenPair:
        normalized_identifier = self.normalize_identifier(actor_type, identifier)
        async with self._uow_factory() as uow:
            principal = await uow.principals.get_by_identifier(actor_type, normalized_identifier)
            password_hash = principal.password_hash if principal is not None else None
            password_matches = self._password_hasher.verify(password, password_hash)
            if principal is None or not password_matches:
                raise InvalidCredentialsError
            if not principal.is_active:
                raise InactivePrincipalError

            authorization = await uow.authorization.get_for_principal(principal.id)
            pair, stored_tokens = self._build_token_pair(
                principal, authorization, family_id=uuid4()
            )
            await uow.tokens.add_many(stored_tokens)
            await uow.commit()
            return pair

    async def validate_access_token(self, token: str) -> AuthenticatedPrincipal:
        claims = self._token_codec.decode(token, TokenType.ACCESS)
        now = self._now_epoch()
        async with self._uow_factory() as uow:
            stored_token = await uow.tokens.get(claims.jti)
            self._ensure_stored_token_matches(stored_token, claims, now)
            principal = await uow.principals.get_by_id(claims.subject)
            if principal is None:
                raise InvalidTokenError
            if not principal.is_active:
                raise InactivePrincipalError
            if principal.actor_type is not claims.actor_type:
                raise InvalidTokenError

            authorization = await uow.authorization.get_for_principal(principal.id)
            return AuthenticatedPrincipal(
                principal=principal,
                authorization=authorization,
                token_jti=claims.jti,
                token_family_id=claims.family_id,
                expires_at=claims.expires_at,
            )

    async def refresh(self, refresh_token: str) -> TokenPair:
        claims = self._token_codec.decode(refresh_token, TokenType.REFRESH)
        now = self._now_epoch()
        async with self._uow_factory() as uow:
            stored_token = await uow.tokens.get(claims.jti)
            if stored_token is None or not self._stored_token_identity_matches(
                stored_token, claims
            ):
                raise InvalidTokenError
            if stored_token.revoked_at is not None:
                await uow.tokens.revoke_family(claims.family_id, now)
                await uow.commit()
                raise InvalidTokenError("Refresh token reuse detected")
            if stored_token.expires_at <= now:
                raise InvalidTokenError

            principal = await uow.principals.get_by_id(claims.subject)
            if principal is None:
                raise InvalidTokenError
            if not principal.is_active:
                raise InactivePrincipalError
            if principal.actor_type is not claims.actor_type:
                raise InvalidTokenError

            authorization = await uow.authorization.get_for_principal(principal.id)
            pair, new_tokens = self._build_token_pair(
                principal, authorization, family_id=claims.family_id
            )
            new_refresh = next(
                token for token in new_tokens if token.token_type is TokenType.REFRESH
            )
            rotated = await uow.tokens.revoke_if_active(claims.jti, now, new_refresh.jti)
            if not rotated:
                await uow.tokens.revoke_family(claims.family_id, now)
                await uow.commit()
                raise InvalidTokenError("Refresh token reuse detected")

            await uow.tokens.add_many(new_tokens)
            await uow.commit()
            return pair

    async def logout(self, refresh_token: str) -> None:
        claims = self._token_codec.decode(refresh_token, TokenType.REFRESH)
        now = self._now_epoch()
        async with self._uow_factory() as uow:
            stored_token = await uow.tokens.get(claims.jti)
            if stored_token is None or not self._stored_token_identity_matches(
                stored_token, claims
            ):
                raise InvalidTokenError
            await uow.tokens.revoke_family(claims.family_id, now)
            await uow.commit()

    def _build_token_pair(
        self,
        principal: Principal,
        authorization: Authorization,
        family_id: UUID,
    ) -> tuple[TokenPair, tuple[StoredToken, StoredToken]]:
        issued_at = self._now_epoch()
        access_jti = uuid4()
        refresh_jti = uuid4()
        access_expires_at = issued_at + self._access_ttl
        refresh_expires_at = issued_at + self._refresh_ttl
        permissions = tuple(sorted(authorization.permissions))

        access_claims = TokenClaims(
            issuer=self._issuer,
            audience=self._audience,
            subject=principal.id,
            jti=access_jti,
            family_id=family_id,
            actor_type=principal.actor_type,
            token_type=TokenType.ACCESS,
            issued_at=issued_at,
            expires_at=access_expires_at,
            admin=authorization.is_admin,
            permissions=permissions,
        )
        refresh_claims = TokenClaims(
            issuer=self._issuer,
            audience=self._audience,
            subject=principal.id,
            jti=refresh_jti,
            family_id=family_id,
            actor_type=principal.actor_type,
            token_type=TokenType.REFRESH,
            issued_at=issued_at,
            expires_at=refresh_expires_at,
        )
        pair = TokenPair(
            access_token=self._token_codec.encode(access_claims),
            refresh_token=self._token_codec.encode(refresh_claims),
            access_expires_at=access_expires_at,
            refresh_expires_at=refresh_expires_at,
        )
        stored_tokens = (
            StoredToken(
                jti=access_jti,
                principal_id=principal.id,
                family_id=family_id,
                token_type=TokenType.ACCESS,
                issued_at=issued_at,
                expires_at=access_expires_at,
            ),
            StoredToken(
                jti=refresh_jti,
                principal_id=principal.id,
                family_id=family_id,
                token_type=TokenType.REFRESH,
                issued_at=issued_at,
                expires_at=refresh_expires_at,
            ),
        )
        return pair, stored_tokens

    @staticmethod
    def _stored_token_identity_matches(stored_token: StoredToken, claims: TokenClaims) -> bool:
        return (
            stored_token.principal_id == claims.subject
            and stored_token.family_id == claims.family_id
            and stored_token.token_type is claims.token_type
            and stored_token.issued_at == claims.issued_at
            and stored_token.expires_at == claims.expires_at
        )

    def _ensure_stored_token_matches(
        self, stored_token: StoredToken | None, claims: TokenClaims, now: int
    ) -> None:
        if stored_token is None or not self._stored_token_identity_matches(stored_token, claims):
            raise InvalidTokenError
        if stored_token.revoked_at is not None or stored_token.expires_at <= now:
            raise InvalidTokenError

    def _now_epoch(self) -> int:
        return int(self._clock.now().astimezone(UTC).timestamp())

    @staticmethod
    def validate_password(password: str) -> None:
        if not PASSWORD_MIN_LENGTH <= len(password) <= PASSWORD_MAX_LENGTH:
            raise InvalidInputError(
                f"Password must have {PASSWORD_MIN_LENGTH} to {PASSWORD_MAX_LENGTH} characters"
            )

    @staticmethod
    def normalize_identifier(actor_type: ActorType, identifier: str) -> str:
        normalized = identifier.strip().casefold()
        if actor_type is ActorType.HUMAN:
            if (
                not normalized
                or len(normalized) > HUMAN_IDENTIFIER_MAX_LENGTH
                or normalized.count("@") != 1
            ):
                raise InvalidInputError("A valid email address is required")
            return normalized

        if not AGENT_IDENTIFIER_MIN_LENGTH <= len(normalized) <= AGENT_IDENTIFIER_MAX_LENGTH:
            raise InvalidInputError(
                f"Agent username must have {AGENT_IDENTIFIER_MIN_LENGTH} to "
                f"{AGENT_IDENTIFIER_MAX_LENGTH} characters"
            )
        if AGENT_IDENTIFIER_PATTERN.fullmatch(normalized) is None:
            raise InvalidInputError("Agent username contains invalid characters")
        return normalized
