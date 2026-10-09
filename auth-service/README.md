# Authentication Service PoC

Servicio HTTP de autenticación construido con FastAPI, SQLite y JWT. Soporta identidades
humanas y agentes, access tokens de una hora, refresh tokens de siete días, rotación segura,
revocación por familia, roles y permisos.

## Requisitos

- CPython 3.14.x instalado localmente.
- `uv` 0.12 o posterior.

El proyecto declara `requires-python = ">=3.14,<3.15"`. Para usar explícitamente el intérprete
instalado en esta máquina sin permitir descargas de Python:

```bash
uv sync \
  --python /home/jeoliver/.local/bin/python \
  --no-managed-python \
  --no-python-downloads
```

## Configuración

```bash
cp .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Reemplace `AUTH_JWT_SECRET` con el valor generado. Las variables
`AUTH_BOOTSTRAP_ADMIN_EMAIL` y `AUTH_BOOTSTRAP_ADMIN_PASSWORD` crean el primer administrador
de forma idempotente. Si ya existe un administrador, su contraseña no se modifica.

## Base de datos

```bash
uv run alembic upgrade head
```

El servicio almacena únicamente hashes Argon2 y metadatos de los tokens. Nunca persiste
contraseñas ni JWT completos.

## Ejecución

```bash
uv run uvicorn auth_service.main:app --reload
```

La documentación OpenAPI estará disponible en `http://127.0.0.1:8000/docs`.

## Endpoints

```text
POST /api/v1/auth/humans/register
POST /api/v1/auth/agents/register
POST /api/v1/auth/login
POST /api/v1/auth/refresh
GET  /api/v1/auth/validate
POST /api/v1/auth/logout
```

Registro humano:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/humans/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"person@example.com","password":"correct-horse"}'
```

Registro de agente:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/agents/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"report-agent","password":"correct-horse"}'
```

Inicio de sesión:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"actor_type":"human","identifier":"person@example.com","password":"correct-horse"}'
```

Validación:

```bash
curl http://127.0.0.1:8000/api/v1/auth/validate \
  -H 'Authorization: Bearer ACCESS_TOKEN'
```

## Claims JWT

El access token contiene:

```json
{
  "iss": "auth-service",
  "aud": "mcp-api",
  "sub": "principal-uuid",
  "jti": "token-uuid",
  "family_id": "session-uuid",
  "actor_type": "human",
  "admin": false,
  "permissions": ["profile:read"],
  "token_type": "access",
  "iat": 1800000000,
  "exp": 1800003600
}
```

`aud` mantiene su semántica JWT estándar. `actor_type` diferencia humanos y agentes. El
refresh token no contiene `admin` ni `permissions`; ambos se recalculan desde SQLite durante
la rotación.

## Calidad

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```
