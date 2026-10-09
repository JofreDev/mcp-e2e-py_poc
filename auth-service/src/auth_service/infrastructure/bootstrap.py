from datetime import UTC, datetime
from uuid import uuid4

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from auth_service.application.auth_service import AuthService
from auth_service.application.ports import PasswordHasher
from auth_service.config import Settings
from auth_service.domain.models import ActorType
from auth_service.infrastructure.database import (
    PermissionRecord,
    PrincipalRecord,
    RoleRecord,
    principal_roles,
    role_permissions,
)

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "user": frozenset({"profile:read"}),
    "agent": frozenset({"fx:read", "profile:read"}),
    "admin": frozenset(
        {
            "profile:read",
            "users:read",
            "users:create",
            "users:update",
            "agents:read",
            "agents:create",
            "agents:update",
        }
    ),
}


async def seed_authorization(
    session_factory: async_sessionmaker[AsyncSession],
) -> None:
    async with session_factory.begin() as session:
        roles = {role.name: role for role in (await session.scalars(select(RoleRecord))).all()}
        for role_name in ROLE_PERMISSIONS:
            if role_name not in roles:
                role_record = RoleRecord(name=role_name)
                session.add(role_record)
                roles[role_name] = role_record

        permission_names = set().union(*ROLE_PERMISSIONS.values())
        permissions = {
            permission.name: permission
            for permission in (await session.scalars(select(PermissionRecord))).all()
        }
        for permission_name in permission_names:
            if permission_name not in permissions:
                permission_record = PermissionRecord(name=permission_name)
                session.add(permission_record)
                permissions[permission_name] = permission_record
        await session.flush()

        existing_links = {
            (role_id, permission_id)
            for role_id, permission_id in (await session.execute(select(role_permissions))).all()
        }
        for role_name, role_permission_names in ROLE_PERMISSIONS.items():
            role_id = roles[role_name].id
            for permission_name in role_permission_names:
                permission_id = permissions[permission_name].id
                if (role_id, permission_id) not in existing_links:
                    await session.execute(
                        insert(role_permissions).values(
                            role_id=role_id,
                            permission_id=permission_id,
                        )
                    )


async def bootstrap_administrator(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings,
    password_hasher: PasswordHasher,
) -> None:
    if settings.bootstrap_admin_email is None or settings.bootstrap_admin_password is None:
        return

    email = AuthService.normalize_identifier(ActorType.HUMAN, str(settings.bootstrap_admin_email))
    async with session_factory.begin() as session:
        administrator_exists = await session.scalar(
            select(PrincipalRecord.id)
            .join(
                principal_roles,
                principal_roles.c.principal_id == PrincipalRecord.id,
            )
            .join(RoleRecord, RoleRecord.id == principal_roles.c.role_id)
            .where(RoleRecord.name == "admin")
            .limit(1)
        )
        if administrator_exists is not None:
            return

        existing_principal = await session.scalar(
            select(PrincipalRecord.id).where(
                PrincipalRecord.actor_type == ActorType.HUMAN.value,
                PrincipalRecord.identifier == email,
            )
        )
        if existing_principal is not None:
            raise RuntimeError(
                "Bootstrap administrator email belongs to a non-administrator identity"
            )

        now = datetime.now(tz=UTC)
        principal_id = str(uuid4())
        session.add(
            PrincipalRecord(
                id=principal_id,
                actor_type=ActorType.HUMAN.value,
                identifier=email,
                password_hash=password_hasher.hash(
                    settings.bootstrap_admin_password.get_secret_value()
                ),
                is_active=True,
                created_at=now,
                updated_at=now,
            )
        )
        await session.flush()

        role_rows = (
            await session.execute(
                select(RoleRecord.id, RoleRecord.name).where(RoleRecord.name.in_(("user", "admin")))
            )
        ).all()
        if len(role_rows) != 2:
            raise RuntimeError("Authorization roles have not been seeded")
        for role_id, _ in role_rows:
            await session.execute(
                insert(principal_roles).values(
                    principal_id=principal_id,
                    role_id=role_id,
                )
            )
