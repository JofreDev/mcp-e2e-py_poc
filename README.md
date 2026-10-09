# MCP E2E Python PoC

Monorepo para probar autenticacion y autorizacion de herramientas MCP. Docker Compose
inicia los dos servicios y conserva la base de datos SQLite en un volumen Docker.

## Componentes

- [`auth-service`](./auth-service): servicio FastAPI que registra identidades, emite JWT y
  valida tokens de acceso.
- [`mcp-service`](./mcp-service): servidor MCP Streamable HTTP con la herramienta
  `convert_currency`, protegida por el permiso `fx:read`.

Los agentes reciben `fx:read`. Las identidades humanas y administradoras no reciben ese
permiso y no pueden ejecutar la herramienta.

## Levantar con Docker

Requiere Docker Desktop con Docker Compose v2.

1. Construya e inicie los servicios:

   ```bash
   docker compose up --build --wait
   docker compose ps
   ```

   En el primer arranque, `auth-service` genera automáticamente un secreto JWT aleatorio
   y lo guarda con permisos restringidos dentro del volumen `auth-data`. Se reutiliza en
   reinicios, por lo que las sesiones permanecen válidas.

2. Opcionalmente, copie `.env.example` a `.env` para cambiar los puertos o definir
   explícitamente `AUTH_JWT_SECRET`. Esto es necesario si quiere controlar el secreto o
   desplegar fuera de un entorno local de prueba.

Espere hasta que ambos servicios tengan estado `healthy`. Las URLs locales son:

- Swagger de autenticacion: `http://127.0.0.1:8000/docs`
- Salud: `http://127.0.0.1:8000/health`
- Endpoint MCP Streamable HTTP: `http://127.0.0.1:8001/mcp`

Los puertos se publican solo en `127.0.0.1`. El MCP resuelve el servicio de autenticacion
por la red privada de Docker usando `http://auth-service:8000`.

Para detenerlos sin borrar identidades ni tokens:

```bash
docker compose down
```

Para borrar tambien todos los datos de SQLite:

```bash
docker compose down -v
```

## Primera Operacion

Con los contenedores saludables, el siguiente script estandar de Python registra un agente,
inicia sesion, inicializa una sesion MCP y convierte 10 EUR a USD mediante Frankfurter:

```bash
python scripts/mcp_smoke_test.py
```

La salida contiene la respuesta JSON-RPC de MCP. Dentro de `result.content` aparecera el
importe convertido, el tipo de cambio y la fecha efectiva. El script no necesita paquetes
adicionales y crea una identidad efimera nueva en cada ejecucion.
Respeta los valores `AUTH_SERVICE_PORT` y `MCP_SERVICE_PORT` definidos en `.env`.

## Para Explorar

Consulte directamente el estado de los contenedores y sus logs:

```bash
docker compose ps
docker compose logs -f auth-service
docker compose logs -f mcp-service
```

Pruebe una conversion historica:

```bash
python scripts/mcp_smoke_test.py --amount 25 --from-currency EUR --to-currency USD --date 2024-05-15
```

Pruebe la autorizacion negativa. Una identidad humana se autentica correctamente, pero la
tool devuelve un error porque no posee `fx:read`:

```bash
python scripts/mcp_smoke_test.py --actor-type human
```

Puede cambiar el par de monedas o el importe:

```bash
python scripts/mcp_smoke_test.py --amount 100 --from-currency GBP --to-currency JPY
```

Para explorar los endpoints de registro, login, refresh, validacion y logout manualmente,
abra Swagger. Para conectar un cliente MCP compatible, configure Streamable HTTP con la URL
`http://127.0.0.1:8001/mcp` y reenvie el JWT de una identidad `agent` como cabecera
`Authorization: Bearer <access_token>` en cada solicitud.

## Desarrollo Local

Cada servicio conserva su configuracion, dependencias y lockfile independiente. Consulte
los README de [`auth-service`](./auth-service) y [`mcp-service`](./mcp-service) para usar
`uv` sin Docker.
