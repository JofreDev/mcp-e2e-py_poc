from collections.abc import Sequence
from types import TracebackType
from typing import Any, cast
from uuid import UUID

from sqlalchemy import insert, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_service.application.ports import (
    AuthorizationRepository,
    PrincipalRepository,
    TokenRepository,
)
from auth_service.domain.errors import PrincipalAlreadyExistsError
from auth_service.domain.models import (
    ActorType,
    Authorization,
    Principal,
    StoredToken,
    TokenType,
)
from auth_service.infrastructure.database import (
    AuthTokenRecord,
    PermissionRecord,
    PrincipalRecord,
    RoleRecord,
    principal_roles,
    role_permissions,
)


def _to_principal(record: PrincipalRecord) -> Principal:
    return Principal(
        id=UUID(record.id),
        actor_type=ActorType(record.actor_type),
        identifier=record.identifier,
        password_hash=record.password_hash,
        is_active=record.is_active,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


def _to_stored_token(record: AuthTokenRecord) -> StoredToken:
    return StoredToken(
        jti=UUID(record.jti),
        principal_id=UUID(record.principal_id),
        family_id=UUID(record.family_id),
        token_type=TokenType(record.token_type),
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        revoked_at=record.revoked_at,
        replaced_by_jti=UUID(record.replaced_by_jti) if record.replaced_by_jti else None,
    )


class SqlAlchemyPrincipalRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_identifier(self, actor_type: ActorType, identifier: str) -> Principal | None:
        statement = select(PrincipalRecord).where(
            PrincipalRecord.actor_type == actor_type.value,
            PrincipalRecord.identifier == identifier,
        )
        record = await self._session.scalar(statement)
        return _to_principal(record) if record is not None else None

    async def get_by_id(self, principal_id: UUID) -> Principal | None:
        record = await self._session.get(PrincipalRecord, str(principal_id))
        return _to_principal(record) if record is not None else None

    async def add(self, principal: Principal) -> None:
        self._session.add(
            PrincipalRecord(
                id=str(principal.id),
                actor_type=principal.actor_type.value,
                identifier=principal.identifier,
                password_hash=principal.password_hash,
                is_active=principal.is_active,
                created_at=principal.created_at,
                updated_at=principal.updated_at,
            )
        )
        await self._session.flush()


class SqlAlchemyAuthorizationRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_for_principal(self, principal_id: UUID) -> Authorization:
        role_statement = (
            select(RoleRecord.name)
            .join(principal_roles, principal_roles.c.role_id == RoleRecord.id)
            .where(principal_roles.c.principal_id == str(principal_id))
        )
        permission_statement = (
            select(PermissionRecord.name)
            .join(
                role_permissions,
                role_permissions.c.permission_id == PermissionRecord.id,
            )
            .join(RoleRecord, RoleRecord.id == role_permissions.c.role_id)
            .join(principal_roles, principal_roles.c.role_id == RoleRecord.id)
            .where(principal_roles.c.principal_id == str(principal_id))
            .distinct()
        )
        roles = frozenset((await self._session.scalars(role_statement)).all())
        permissions = frozenset((await self._session.scalars(permission_statement)).all())
        return Authorization(roles=roles, permissions=permissions)

    async def assign_role(self, principal_id: UUID, role_name: str) -> None:
        role_id = await self._session.scalar(
            select(RoleRecord.id).where(RoleRecord.name == role_name)
        )
        if role_id is None:
            raise RuntimeError(f"Role '{role_name}' has not been seeded")
        await self._session.execute(
            insert(principal_roles).values(
                principal_id=str(principal_id),
                role_id=role_id,
            )
        )


class SqlAlchemyTokenRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get(self, jti: UUID) -> StoredToken | None:
        record = await self._session.get(AuthTokenRecord, str(jti))
        return _to_stored_token(record) if record is not None else None

    async def add_many(self, tokens: Sequence[StoredToken]) -> None:
        self._session.add_all(
            [
                AuthTokenRecord(
                    jti=str(token.jti),
                    principal_id=str(token.principal_id),
                    family_id=str(token.family_id),
                    token_type=token.token_type.value,
                    issued_at=token.issued_at,
                    expires_at=token.expires_at,
                    revoked_at=token.revoked_at,
                    replaced_by_jti=(str(token.replaced_by_jti) if token.replaced_by_jti else None),
                )
                for token in tokens
            ]
        )

    async def revoke_if_active(self, jti: UUID, revoked_at: int, replaced_by_jti: UUID) -> bool:
        result = await self._session.execute(
            update(AuthTokenRecord)
            .where(
                AuthTokenRecord.jti == str(jti),
                AuthTokenRecord.revoked_at.is_(None),
            )
            .values(
                revoked_at=revoked_at,
                replaced_by_jti=str(replaced_by_jti),
            )
        )
        return cast(CursorResult[Any], result).rowcount == 1

    async def revoke_family(self, family_id: UUID, revoked_at: int) -> None:
        await self._session.execute(
            update(AuthTokenRecord)
            .where(
                AuthTokenRecord.family_id == str(family_id),
                AuthTokenRecord.revoked_at.is_(None),
            )
            .values(revoked_at=revoked_at)
        )


class SqlAlchemyUnitOfWork:
    principals: PrincipalRepository
    authorization: AuthorizationRepository
    tokens: TokenRepository

    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory
        self._session: AsyncSession

    async def __aenter__(self) -> SqlAlchemyUnitOfWork:
        self._session = self._session_factory()
        self.principals = SqlAlchemyPrincipalRepository(self._session)
        self.authorization = SqlAlchemyAuthorizationRepository(self._session)
        self.tokens = SqlAlchemyTokenRepository(self._session)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is not None:
            await self._session.rollback()
        await self._session.close()

    async def commit(self) -> None:
        try:
            await self._session.commit()
        except IntegrityError as error:
            await self._session.rollback()
            raise PrincipalAlreadyExistsError from error
