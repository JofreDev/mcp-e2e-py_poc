from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from auth_service.api.error_handlers import register_error_handlers
from auth_service.api.routes import router
from auth_service.application.auth_service import AuthService
from auth_service.application.ports import UnitOfWork
from auth_service.config import Settings
from auth_service.infrastructure.bootstrap import (
    bootstrap_administrator,
    seed_authorization,
)
from auth_service.infrastructure.database import Database
from auth_service.infrastructure.repositories import SqlAlchemyUnitOfWork
from auth_service.infrastructure.security import (
    Argon2PasswordHasher,
    JwtTokenCodec,
    SystemClock,
)


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings()  # type: ignore[call-arg]
    database = Database(resolved_settings.database_url)
    clock = SystemClock()
    password_hasher = Argon2PasswordHasher()
    token_codec = JwtTokenCodec(
        secret=resolved_settings.jwt_secret.get_secret_value(),
        algorithm=resolved_settings.jwt_algorithm,
        issuer=resolved_settings.jwt_issuer,
        audience=resolved_settings.jwt_audience,
        clock=clock,
        access_token_ttl_seconds=resolved_settings.access_token_ttl_seconds,
        refresh_token_ttl_seconds=resolved_settings.refresh_token_ttl_seconds,
    )

    def uow_factory() -> UnitOfWork:
        return SqlAlchemyUnitOfWork(database.session_factory)

    auth_service = AuthService(
        uow_factory=uow_factory,
        password_hasher=password_hasher,
        token_codec=token_codec,
        clock=clock,
        issuer=resolved_settings.jwt_issuer,
        audience=resolved_settings.jwt_audience,
        access_token_ttl_seconds=resolved_settings.access_token_ttl_seconds,
        refresh_token_ttl_seconds=resolved_settings.refresh_token_ttl_seconds,
    )

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if resolved_settings.auto_create_schema:
            await database.create_schema()
        await seed_authorization(database.session_factory)
        await bootstrap_administrator(
            database.session_factory,
            resolved_settings,
            password_hasher,
        )
        yield
        await database.dispose()

    app = FastAPI(
        title=resolved_settings.app_name,
        version="0.1.0",
        lifespan=lifespan,
    )
    app.state.auth_service = auth_service
    app.state.database = database

    @app.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(router, prefix="/api/v1")
    register_error_handlers(app)
    return app
