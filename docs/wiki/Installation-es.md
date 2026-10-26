> 🌐 [日本語](Installation) · [English](Installation-en) · [中文](Installation-zh) · **Español**

# Instalación y operación (Docker Compose)

Es la configuración para uso habitual, cercana a producción. Una sola imagen Docker contiene el servidor (API + interfaz web + trabajos en segundo plano) y
todos los roles: Gate, Agent y el simulador. Si solo quiere probarlo en su máquina, [Inicio rápido](Quick-Start-es) es más sencillo.

## Requisitos

- Docker Engine **25 o superior**, Docker Compose **v2.24 o superior**
- x86_64 o arm64 (la compilación en arm64 aún no está verificada)
- Memoria: desde unos 512 MB a escala de laboratorio

## Instalación

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git tokiwa && cd tokiwa
cp .env.example .env     # Descomente solo las líneas necesarias
make up                  # = docker compose -f deploy/compose.yaml --env-file .env up -d --build --wait
```

1. Cree el primer administrador en <http://localhost:8788/setup> (con la CLI:
   `docker compose -f deploy/compose.yaml exec tokiwa tokiwa user create admin --role admin`; la contraseña se introduce de forma interactiva).
2. Si usa un LLM, escriba `ANTHROPIC_API_KEY=...` en `.env` (si no se define, funciona con el LLM simulado).
3. Por defecto solo se publica en `127.0.0.1:8788`. Para exponerlo en la LAN se usa `TOKIWA_BIND=0.0.0.0` en `.env`, pero
   **no lo publique sin TLS**: coloque delante el proxy inverso que se describe más adelante.

> ⚠️ **No habilite ajustes con un valor vacío**. Por ejemplo, `TOKIWA_SERVER__SECRET_KEY=` (vacío) se usaría como "clave de firma de cadena vacía".
> Deje comentadas las opciones que no use. Si no se define, la clave de firma se genera automáticamente en el primer arranque.

### Ejecutar solo con docker

```bash
make docker              # docker build -f deploy/Dockerfile -t tokiwa:local .
docker run -d --name tokiwa --init -p 127.0.0.1:8788:8788 -v tokiwa-data:/data tokiwa:local
```

### Endurecimiento por defecto (compose)

Sistema de archivos raíz de solo lectura (solo se escribe en `/data` y `/tmp`), eliminación de todas las capabilities,
`no-new-privileges`, usuario no root (uid/gid 10001) y rotación de logs (10 MB × 5).

## Ejecutar otros roles con la misma imagen

Si el primer argumento del contenedor es uno de `serve gate agent sim eval intel user token version`, se ejecuta como comando `tokiwa`.

```bash
# Token de API para sensores (se muestra una sola vez)
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1

# Gate (perfil gate de compose; defina TOKIWA_GATE__INGEST_TOKEN y TOKIWA_GATE__UPSTREAM en .env)
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# Sensor de host (usa los espacios de nombres de PID / red del host para ver sus puertos y procesos)
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  -e TOKIWA_AGENT__INGEST_TOKEN=tkw_... -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run
```

- A los roles sin HTTP (agent / sim) se les añade `TOKIWA_HEALTHCHECK_URL=none`. La comprobación de estado de Gate es
  `http://127.0.0.1:8080/__tokiwa/health`.
- Agent puede necesitar privilegios equivalentes a root para leer la información de procesos de otros usuarios (la imagen no se ejecuta como root).
  Si el objetivo es supervisar el host, lo más sencillo es instalarlo directamente en el host. Más detalles en [Conexión de sensores](Sensors-es).

## Cambiar a PostgreSQL

SQLite está pensado para laboratorios y entornos pequeños. Con volúmenes de eventos grandes, use PostgreSQL. Defina lo siguiente en `.env` y ejecute `make up`.

```bash
COMPOSE_PROFILES=postgres
POSTGRES_USER=tokiwa
POSTGRES_PASSWORD=<salida de openssl rand -hex 24>
TOKIWA_DATABASE__URL=postgresql+asyncpg://${POSTGRES_USER}:${POSTGRES_PASSWORD}@postgres:5432/tokiwa
```

- Las tablas se crean automáticamente al arrancar. PostgreSQL no se expone al host (solo dentro de la red de compose).
- **Todavía no existe una herramienta de migración de datos** de SQLite a PostgreSQL (se empieza con una base de datos nueva).

## Detrás de un proxy inverso

- **Publíquelo en la raíz de un dominio (o subdominio)**. La publicación en una subruta como `/tokiwa/` no está soportada.
- Defina `TOKIWA_SERVER__BASE_URL=https://tokiwa.example.internal` (se usa, por ejemplo, en los enlaces de las notificaciones).
- Para las actualizaciones en tiempo real (SSE: `/api/v1/stream`), **desactive el búfer y alargue el tiempo de espera**.
- Si el proxy está en otro host u otro contenedor, defina `FORWARDED_ALLOW_IPS=<IP/CIDR del proxy>`.

Ejemplo de nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    client_max_body_size 20m;                  # Para los lotes de ingesta de los sensores

    location /api/v1/stream {
        proxy_pass http://127.0.0.1:8788;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 1h;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location / {
        proxy_pass http://127.0.0.1:8788;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Ejemplo de Caddy:

```caddyfile
tokiwa.example.internal {
    reverse_proxy 127.0.0.1:8788 {
        flush_interval -1
    }
}
```

Si añade en el proxy una capa de autenticación como SSO, tenga en cuenta que `/api/v1/ingest/events` y `/api/v1/gate/policy`, que usan los sensores,
se autentican con tokens de API: excluya esas rutas o haga que los sensores apunten directamente a :8788 a través de la red interna.

## Copia de seguridad y restauración

Hay que guardar dos cosas: la **base de datos** y la **clave de firma `secret.key`** (ambas en `/data`). Si se pierde `secret.key`,
las sesiones iniciadas dejan de ser válidas (los tokens de API no se ven afectados, porque se guardan como hashes en la base de datos).

SQLite funciona en modo WAL, así que no copie el archivo directamente mientras está en funcionamiento; use la API de copia de seguridad en línea.

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

Para restaurar, reemplace los archivos con el servicio detenido.

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
$C run --rm --entrypoint sh tokiwa -c 'rm -f /data/tokiwa.db-wal /data/tokiwa.db-shm'
$C start tokiwa
```

Con PostgreSQL, use `pg_dump -Fc` / `pg_restore` y guarde `secret.key` por separado.

## Actualización

```bash
git pull
make up                  # Recompila y reemplaza (se conserva el volumen /data)
```

> ⚠️ **Todavía no hay migración automática del esquema**. Al arrancar solo se "crean las tablas que faltan";
> no se añaden ni se modifican columnas de las tablas existentes. Haga siempre una copia de seguridad antes de actualizar.
> Está previsto introducir una herramienta de migración (Alembic) en la próxima fase de desarrollo.

## Comandos auxiliares de desarrollo y operación (make)

| Comando | Descripción |
|---|---|
| `make dev` | Arranca a la vez la API (:8788, recarga automática) y la interfaz (:5173) |
| `make test` / `make lint` / `make build` | Pruebas / lint / compilación de la interfaz |
| `make up` / `make down` / `make logs` | Arranque, parada y logs de `deploy/compose.yaml` |
| `make lab` | Arranque del laboratorio (`lab/compose.yaml`) |
| `make seed` | Envía eventos sintéticos de demostración al servidor local (destino solo localhost) |
| `make docker` / `make docker-smoke` | Compilación de la imagen / prueba de humo |
