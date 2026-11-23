> 🌐 [日本語](Sensors) · [English](Sensors-en) · [中文](Sensors-zh) · **Español**

# Conexión de sensores

El servidor de TOKIWA no sale a recopilar datos por sí mismo: analiza los **eventos que le envían los sensores**.
Hay 3 tipos de sensores, que pueden combinarse.

| Sensor | Qué ve | Uso recomendado |
|---|---|---|
| **TOKIWA Gate** | La solicitud HTTP completa (**incluido el cuerpo**) y el estado de la respuesta | Protección de aplicaciones web y API. Gate también ejecuta los bloqueos y los señuelos |
| **TOKIWA Agent** | Puertos en escucha y conexiones del host, logs JSON de nginx / Caddy, Suricata, Zeek | Supervisión de servidores, ingesta de logs existentes |
| **API de ingesta (directa)** | Lo que usted envíe (por ejemplo, los prompts de una aplicación LLM) | Integraciones propias |

## Tokens de API

Los sensores no se autentican con el inicio de sesión de un usuario, sino con un **token de API**.

```bash
cd backend
uv run tokiwa token create gate-1 --scope ingest --scope gate   # para Gate: añada el ámbito gate explícitamente
uv run tokiwa token create agent-web01            # ámbito por defecto: solo ingest
```

| Ámbito | Qué permite |
|---|---|
| `ingest` | Enviar eventos (`POST /api/v1/ingest/events`) |
| `gate` | Obtener la política de Gate (`GET /api/v1/gate/policy`) |
| `read` | Reservado (en v0.1 todavía no hay ninguna API que use este ámbito) |

- El token (`tkw_...`) se muestra **una sola vez, al crearlo**. En la base de datos solo se guarda su hash.
- También pueden crearse y revocarse en **Settings → API tokens** (Configuración → Tokens de API) de la interfaz web (solo administradores).
- Si se pasa como argumento de línea de comandos, otros usuarios pueden verlo con `ps`; páselo **mediante una variable de entorno o un archivo**.
- `--sensor-id` / `--dataset` **vinculan** un token a IDs de sensor y datasets concretos (sin restricción si se omiten).
  Si un token vinculado envía un dataset fuera de su lista, se rechaza el lote entero con 403; si declara otro ID de sensor,
  se sustituye por uno permitido. Se recomienda vincular los tokens de los sensores que no son Gate
  (p. ej. `--sensor-id web01 --dataset nginx.access --dataset 'host.*'`).
- El servidor registra en cada evento el token que lo entregó, en las etiquetas `ingest.token` / `ingest.token_id`. Los datos
  propios de Gate (`gate.*` / `deception.*`) enviados por un token sin el ámbito `gate` se etiquetan `ingest.trust=low`.
  Para que eventos falsificados no hagan bloquear una IP inocente, ponga las IP de socios, CDN y de salida propias en `response.protected_cidrs`.

## TOKIWA Gate (sensor de tipo proxy inverso)

Es un proxy inverso que se coloca delante de la aplicación web que desea proteger. Captura incluso el cuerpo de las solicitudes, que no aparece en los logs de acceso,
y aplica al instante las políticas que distribuye el servidor (bloqueo, limitación de tasa, tarpit, señuelos).

```
Cliente ──▶ Gate (:8080) ──▶ Aplicación protegida
              │ envío de eventos / obtención de políticas (cada 5 s por defecto)
              ▼
         TOKIWA Server (:8788)
```

### Arranque

```bash
cd backend
export TOKIWA_GATE__INGEST_TOKEN=tkw_...          # O bien --token-file <path>
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 0.0.0.0:8080 --server http://127.0.0.1:8788
```

A continuación, cambie el destino del DNS o del balanceador de carga para que los usuarios accedan a través de Gate (:8080).

### Ajustes principales

El orden de prioridad de los ajustes es "flag de la CLI > variables de entorno `TOKIWA_GATE__*` > `tokiwa.yaml` > valor por defecto".

| Ajuste | CLI | Por defecto | Descripción |
|---|---|---|---|
| upstream | `--upstream` | `http://127.0.0.1:3000` | Destino del reenvío. También admite un prefijo de ruta (`http://app/base`) |
| listen | `--listen host:port` | `0.0.0.0:8080` | Dirección de escucha |
| server_url | `--server` | `http://127.0.0.1:8788` | Servidor de TOKIWA |
| ingest_token | `--token` / `--token-file` | Ninguno | Requiere los ámbitos `ingest` y `gate` |
| capture_body_bytes | `--capture-body-bytes` | 4096 | Número de bytes iniciales del cuerpo de la solicitud que se capturan (0 = no capturar) |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | Intervalo de obtención de la política |
| trust_forwarded_for | `--trust-forwarded-for` | false | Toma el valor **más a la derecha** de `X-Forwarded-For` como IP de origen |
| max_request_headers | — (`TOKIWA_GATE__MAX_REQUEST_HEADERS`) | 100 | Las solicitudes con más líneas de encabezado reciben 431 en lugar de reenviarse (0 = sin límite) |
| forward_client_headers | — (`TOKIWA_GATE__FORWARD_CLIENT_HEADERS`) | `[]` | Encabezados que normalmente se eliminan (ver abajo) y que se pasan sin cambios al upstream |
| tarpit_max_concurrent / tarpit_max_per_client | — | 256 / 8 | Máximo de solicitudes retenidas a la vez por el tarpit (en total / por IP); las que excedan reciben 429 (0 = sin límite) |

Opciones operativas disponibles solo en la CLI: `--upstream-timeout` (30 s), `--max-queue` (límite de eventos pendientes de envío: 10 000),
`--preserve-host / --rewrite-host`, `--access-log`, `--limit-concurrency` (límite de conexiones simultáneas; por encima, 503; sin límite por defecto).

### Comportamientos que conviene conocer

- **Use `--trust-forwarded-for` solo detrás de un balanceador de carga de confianza**. Sin esta opción, los encabezados
  `X-Forwarded-*` enviados por el cliente se descartan y se sustituyen por los valores observados por Gate (para impedir la suplantación de la IP de origen).
- Los demás encabezados que declaran una IP o un esquema de cliente (`X-Real-IP`, `Forwarded`, `True-Client-IP`, `CF-Connecting-IP`, ...) y `X-Original-URL` /
  `X-Rewrite-URL` **no se pasan al upstream**. En su lugar, Gate pone en `X-Real-IP` y `Forwarded` la IP de cliente que ha determinado.
  Si el upstream lee un encabezado que añade un proxy delante (por ejemplo, Cloudflare), inclúyalo en `forward_client_headers` (p. ej. `["cf-connecting-ip"]`).
  Gate tampoco añade un `User-Agent` ni otros encabezados que el cliente no haya enviado.
- Al comparar con los señuelos, las diferencias de mayúsculas, una `/` o un `.` final, lo que sigue a `;`, `%5c` (`\`) y la doble codificación cuentan como la misma ruta
  (`/.ENV` y `/.env;x` también activan un señuelo `/.env`). Las rutas con estas variaciones llevan la etiqueta `gate:path_anomaly`.
- Las respuestas que genera el propio Gate (403 de bloqueo, señuelos, 502/504 por fallos del upstream, ...) llevan `Cache-Control: no-store`. Si hay una CDN delante de Gate,
  compruebe que no esté configurada para forzar la caché de los 404 y respuestas similares.
- Los cuerpos de solicitud con `Content-Encoding: gzip` / `deflate` se registran descomprimidos (etiqueta `gate:req_encoded`; el upstream sigue recibiendo los bytes comprimidos).
  br y zstd no se pueden descomprimir; solo queda la etiqueta `gate:req_encoding_unknown`.
- Los datos capturados **se enmascaran en Gate antes de enviarlos** (valores de encabezados como `Authorization` o `Cookie`,
  valores de parámetros como `password=`, tokens, claves, direcciones de correo electrónico, etc.).
- Los eventos conservan hasta 64 encabezados distintos. Los que se usan para la detección (User-Agent, Referer, `Sec-Fetch-*`, `X-Forwarded-*`, ...)
  se conservan siempre, estén donde estén; el resto queda indicado con la etiqueta `gate:headers_truncated` y el número de encabezados (label `gate.header_count`).
- **fail-open**: aunque el servidor de TOKIWA se detenga, el proxy de Gate sigue funcionando (los eventos se acumulan temporalmente y se reenvían).
- **fail-static**: si no puede obtener la política, mantiene la última (para no abrir la vía de "tumbar el servidor para que se levanten los bloqueos"). Aun así, el Gate respeta el vencimiento (TTL) de cada bloqueo: las entradas vencidas se levantan.
- Comprobación de estado: `GET /__tokiwa/health` → `{"status":"ok"}`. Desde IP locales/privadas devuelve también estadísticas de envío, entre otros datos.
- No soportado: WebSocket (devuelve 501), upstream HTTP/2, gRPC. Gate está pensado para funcionar como un único proceso.

## TOKIWA Agent (sensor de host y reenvío de logs)

```bash
cd backend
export TOKIWA_AGENT__INGEST_TOKEN=tkw_...
uv run tokiwa agent run --server-url http://tokiwa.example.internal:8788 \
  --nginx /var/log/nginx/tokiwa.json.log \
  --suricata /var/log/suricata/eve.json
```

| Origen de datos | Opción | Contenido |
|---|---|---|
| Host | `--host-sensor` (activado por defecto), `--connections` (activado por defecto), `--interval` | Lista de puertos en escucha y sus cambios, nuevas conexiones TCP |
| nginx | `--nginx <path>` (puede repetirse) | Logs de acceso en formato JSON (formato definido en `lab/nginx/tokiwa-json.conf` del repositorio) |
| Caddy | `--caddy <path>` | Logs de acceso JSON |
| Suricata | `--suricata <path>` | `eve.json` |
| Zeek | `--zeek-dir <path>` | Directorio de logs o un único archivo |

- Por defecto, los logs se leen **desde el final** (con `--from-beginning`, desde el principio).
- Para comprobar el funcionamiento resulta útil `tokiwa agent once --print` (recopila una sola vez y muestra el JSON sin enviarlo).
- Para leer la información de procesos de otros usuarios pueden necesitarse privilegios equivalentes a root.
- Los puertos en escucha encontrados en la primera instantánea se registran, por defecto (`agent.ports_first_snapshot: info`), con severidad "informativa"
  (con `learn` no se registran: solo se memorizan como línea base). A partir de ahí, se detecta cualquier nuevo puerto en escucha que aparezca.

## API de ingesta (envío directo e integración con aplicaciones LLM)

Para enviar eventos desde un sistema propio, llame directamente a la API de ingesta. Por ejemplo, en una aplicación LLM interna,
puede enviar los prompts de los usuarios a TOKIWA para supervisar la inyección de prompts.

```bash
curl -X POST http://127.0.0.1:8788/api/v1/ingest/events \
  -H "X-Tokiwa-Token: $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "events": [{
      "kind": "llm_app",
      "dataset": "support-bot.prompts",
      "source": {"ip": "203.0.113.10"},
      "llm_app": {"app": "support-bot", "role": "user", "prompt": "Ignore all previous instructions and ..."}
    }]
  }'
```

- El encabezado de autenticación es `X-Tokiwa-Token: tkw_...` o `Authorization: Bearer tkw_...`. Se requiere el ámbito `ingest`.
- Como máximo **5000 eventos** por solicitud. Si se omite `timestamp`, se usa la hora de recepción.
- El cuerpo de la petición admite como máximo 32 MiB por defecto (`server.max_ingest_body_bytes`; si se supera, 413). Un campo de
  texto de más de 65 536 caracteres se trunca conservando el principio, y el evento recibe la etiqueta `truncated` y el label
  `tokiwa.truncated` (`campo:longitud original`). El evento no se rechaza; la detección usa los valores truncados.
- Entre los valores de `kind` están `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom`, entre otros. Para los detalles del esquema, consulte la documentación de la API del servidor (`http://<server>:8788/api/docs`).
- ⚠️ **La API de ingesta no aplica enmascaramiento en el servidor** (Gate y Agent enmascaran antes de enviar).
  Si envía datos directamente, no incluya secretos como contraseñas o tokens. Aun así, los datos siempre se enmascaran justo antes de pasarlos al LLM.

Los chats HTTP en JSON (por defecto, dirigidos a `/api/chat`, `/v1/chat/completions` y `/chat`) pasan automáticamente a ser objeto
de la detección de inyección de prompts si atraviesan Gate (puede cambiarse con `detection.llm_app_paths`).
