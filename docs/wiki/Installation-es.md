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

1. Cree el primer administrador en <http://localhost:8788/setup>. La página pide un **Setup code** (código de configuración): está en el log de arranque (`docker compose -f deploy/compose.yaml logs tokiwa`, que muestra una URL con el código) o se obtiene con
   `docker compose -f deploy/compose.yaml exec tokiwa cat /data/setup-code` (de un solo uso; con la CLI:
   `docker compose -f deploy/compose.yaml exec tokiwa tokiwa user create admin --role admin`; la contraseña se introduce de forma interactiva).
2. Si usa un LLM, escriba `ANTHROPIC_API_KEY=...` en `.env` (si no se define, funciona con el LLM simulado, mock).
3. Por defecto solo se publica en `127.0.0.1:8788`. Para exponerlo en la LAN se usa `TOKIWA_BIND=0.0.0.0` en `.env`, pero
   **no lo publique sin TLS**: coloque delante el proxy inverso que se describe más adelante.

> ⚠️ **No habilite ajustes con un valor vacío** (lo que significa una cadena vacía depende del ajuste). Deje comentadas las opciones que no use.
> La clave de firma `TOKIWA_SERVER__SECRET_KEY` se genera automáticamente en el primer arranque si no se define (o está vacía); una clave definida necesita al menos 32 caracteres.

### Ejecutar solo con docker

```bash
make docker              # docker build -f deploy/Dockerfile -t tokiwa:local .
docker run -d --name tokiwa --init -p 127.0.0.1:8788:8788 -v tokiwa-data:/data tokiwa:local
```

### Endurecimiento por defecto (compose)

Sistema de archivos raíz de solo lectura (solo se escribe en `/data` y `/tmp`), eliminación de todas las capabilities,
`no-new-privileges`, usuario no root (uid/gid 10001) y rotación de logs (10 MB × 5).
También hay un límite de procesos (`pids_limit: 512`). PostgreSQL conserva solo las capabilities que necesita al arrancar (CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID)
y se ejecuta con `no-new-privileges`. No se fija un límite de memoria (uno demasiado bajo haría caer TOKIWA en pleno ataque; ajústelo a su host).
Los servicios de TOKIWA y el victim del laboratorio (`lab/compose.yaml`) tienen el mismo endurecimiento.

### Cómo pasar los secretos

El contenido de `.env` solo llega al contenedor del servidor tokiwa. El contenedor del Gate, que recibe el tráfico de ataque, solo recibe
las variables que usa, como `TOKIWA_GATE__*` (no tiene la clave de firma JWT, la clave de la API del LLM ni la contraseña de la base de datos).

Las variables de entorno se ven con `docker inspect`, así que las claves de API y similares también pueden pasarse como archivos.
`TOKIWA_<AJUSTE>_FILE=<ruta>` (por ejemplo `TOKIWA_LLM__ANTHROPIC_API_KEY_FILE`, `TOKIWA_DATABASE__URL_FILE` o `ANTHROPIC_API_KEY_FILE`)
lee el valor de un archivo. `deploy/compose.secrets.example.yaml` muestra cómo hacerlo con los secrets de Compose. Haga que el usuario del
contenedor (uid 10001) pueda leer los archivos y elimine los mismos valores de `.env` (si están los dos, el servidor no arranca).
Detalles: `docs/deploy.md` §5.

```bash
cp deploy/compose.secrets.example.yaml deploy/compose.secrets.yaml
install -d -m 700 secrets && (umask 077 && "${EDITOR:-vi}" secrets/anthropic_api_key)
sudo chown 10001:10001 secrets/anthropic_api_key
docker compose -f deploy/compose.yaml -f deploy/compose.secrets.yaml --env-file .env up -d
```

## Ejecutar otros roles con la misma imagen

Si el primer argumento del contenedor es uno de `serve gate agent sim eval intel user token version`, se ejecuta como comando `tokiwa`.

```bash
# Token de API para sensores (se muestra una sola vez)
docker compose -f deploy/compose.yaml exec tokiwa tokiwa token create gate-1 --scope ingest --scope gate

# Gate (perfil gate de compose; defina TOKIWA_GATE__INGEST_TOKEN y TOKIWA_GATE__UPSTREAM en .env)
docker compose -f deploy/compose.yaml --env-file .env --profile gate up -d

# Sensor de host (usa los espacios de nombres de PID / red del host para ver sus puertos y procesos)
# Pase el token en un archivo env con permisos 600, /etc/tokiwa/agent.env (una línea: TOKIWA_AGENT__INGEST_TOKEN=tkw_...)
docker run -d --name tokiwa-agent --pid host --network host -e TOKIWA_HEALTHCHECK_URL=none \
  --env-file /etc/tokiwa/agent.env -v /var/log/nginx:/var/log/nginx:ro tokiwa:local agent run
```

- **No pase los tokens de API como argumentos de línea de comandos, como `--token tkw_...`.** Los argumentos son visibles para otros usuarios
  del mismo host mediante `ps`, y para los administradores de Docker mediante `docker inspect`. Use `--token-file` para Gate (se vuelve a leer
  cuando cambia) y la variable de entorno `TOKIWA_AGENT__INGEST_TOKEN` para Agent (`--env-file` o el `.env` de compose). Los pasos están en `docs/deploy.md` §4.
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
  La interfaz se conecta con un ticket de un solo uso válido 60 segundos (`?ticket=`) en la URL, no con su token de sesión (JWT). Por precaución, excluya esta ruta del registro de acceso del proxy (`access_log off;` en el ejemplo siguiente).
- Si el proxy está en otro host u otro contenedor, defina `FORWARDED_ALLOW_IPS=<IP/CIDR del proxy>`.

Ejemplo de nginx:

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name tokiwa.example.internal;
    client_max_body_size 32m;                  # Para los lotes de ingesta de los sensores (igual que server.max_ingest_body_bytes)

    location /api/v1/stream {
        access_log off;                        # la URL lleva un ticket de un solo uso (?ticket=)
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
Guarde también el anillo de claves de engaño `deception.key` (también en `/data`). Si se pierde, cambian las credenciales falsas y los valores de canario de los señuelos, y los valores que un atacante ya obtuvo dejan de detectarse ([Engaño](Deception-es)).

SQLite funciona en modo WAL, así que no copie el archivo directamente mientras está en funcionamiento; use la API de copia de seguridad en línea.

```bash
C="docker compose -f deploy/compose.yaml"
$C exec -T tokiwa python -c "import sqlite3; s=sqlite3.connect('/data/tokiwa.db'); d=sqlite3.connect('/data/backup.db'); s.backup(d); d.close(); s.close()"
mkdir -p backups
$C cp tokiwa:/data/backup.db  "backups/tokiwa-$(date +%F).db"
$C cp tokiwa:/data/secret.key "backups/secret-$(date +%F).key"
$C cp tokiwa:/data/deception.key "backups/deception-$(date +%F).key"
$C exec -T tokiwa rm /data/backup.db
```

Para restaurar, reemplace los archivos con el servicio detenido.

```bash
$C stop tokiwa
$C cp backups/tokiwa-YYYY-MM-DD.db  tokiwa:/data/tokiwa.db
$C cp backups/secret-YYYY-MM-DD.key tokiwa:/data/secret.key
$C cp backups/deception-YYYY-MM-DD.key tokiwa:/data/deception.key
$C run --rm --entrypoint sh tokiwa -c 'rm -f /data/tokiwa.db-wal /data/tokiwa.db-shm'
$C start tokiwa
```

Con PostgreSQL, use `pg_dump -Fc` / `pg_restore` y guarde `secret.key` y `deception.key` por separado.

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
