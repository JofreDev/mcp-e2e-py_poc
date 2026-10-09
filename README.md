# MCP E2E Python PoC

Monorepo con servicios Python independientes para probar autenticacion y autorizacion
de herramientas MCP.

## Componentes

- [`auth-service`](./auth-service): servicio FastAPI que registra identidades, emite JWT y
  valida tokens de acceso.
- [`mcp-service`](./mcp-service): servidor MCP Streamable HTTP con una herramienta de
  conversion de monedas, protegida por el permiso `fx:read`.

## Ejecucion local

Configure, sincronice y ejecute cada servicio desde su propia carpeta. Consulte los
README de cada componente para los requisitos y comandos.

Inicie primero `auth-service` en el puerto `8000`. Despues, en otra terminal, inicie
`mcp-service` en el puerto `8001`. El endpoint MCP sera
`http://127.0.0.1:8001/mcp`.
