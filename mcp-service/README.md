# MCP Service

Servidor FastMCP con transporte Streamable HTTP que convierte monedas mediante Frankfurter.
Cada ejecucion de la herramienta valida el JWT contra `auth-service` y requiere el permiso
`fx:read`, asignado al rol `agent`.

## Requisitos

- CPython 3.14.x.
- `uv` 0.12 o posterior.
- `auth-service` iniciado y migrado.

## Configuracion y ejecucion

```bash
cp .env.example .env
uv sync
uv run mcp-service
```

El endpoint MCP se publica en `http://127.0.0.1:8001/mcp` por defecto. El cliente MCP se
configura con Streamable HTTP y envía `Authorization: Bearer <access_token>` en cada solicitud.
Como se puede observar, el servidor valida cada invocación de forma independiente.

Para obtener un token autorizado, se registra e inicia sesión con una identidad `agent` en
`auth-service`. Los roles `user` y `admin` no tienen acceso a esta herramienta.

## Tool

`convert_currency` recibe `amount`, `from_currency`, `to_currency` y `date` opcional en formato
`YYYY-MM-DD`. Consulta la API v2 de Frankfurter y devuelve el tipo aplicado y el importe
convertido.

## Calidad

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run mypy
```
