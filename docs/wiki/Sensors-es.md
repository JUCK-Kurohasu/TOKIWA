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
uv run tokiwa token create gate-1                    # Ámbitos por defecto: ingest + gate
uv run tokiwa token create agent-web01 --scope ingest
```

| Ámbito | Qué permite |
|---|---|
| `ingest` | Enviar eventos (`POST /api/v1/ingest/events`) |
| `gate` | Obtener la política de Gate (`GET /api/v1/gate/policy`) |
| `read` | Reservado (en v0.1 todavía no hay ninguna API que use este ámbito) |

- El token (`tkw_...`) se muestra **una sola vez, al crearlo**. En la base de datos solo se guarda su hash.
- También pueden crearse y revocarse en **Settings → API tokens** (Configuración → Tokens de API) de la interfaz web (solo administradores).
- Si se pasa como argumento de línea de comandos, otros usuarios pueden verlo con `ps`; páselo **mediante una variable de entorno o un archivo**.

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

El orden de prioridad de los ajustes es "flag de la CLI > variables de entorno `TOKIWA_GATE__*` / `tokiwa.yaml` > valor por defecto".

| Ajuste | CLI | Por defecto | Descripción |
|---|---|---|---|
| upstream | `--upstream` | `http://127.0.0.1:3000` | Destino del reenvío. También admite un prefijo de ruta (`http://app/base`) |
| listen | `--listen host:port` | `0.0.0.0:8080` | Dirección de escucha |
| server_url | `--server` | `http://127.0.0.1:8788` | Servidor de TOKIWA |
| ingest_token | `--token` / `--token-file` | Ninguno | Requiere los ámbitos `ingest` y `gate` |
| capture_body_bytes | `--capture-body-bytes` | 4096 | Número de bytes iniciales del cuerpo de la solicitud que se capturan (0 = no capturar) |
| policy_refresh_seconds | `--policy-refresh` | 5.0 | Intervalo de obtención de la política |
| trust_forwarded_for | `--trust-forwarded-for` | false | Toma el valor **más a la derecha** de `X-Forwarded-For` como IP de origen |

Opciones operativas disponibles solo en la CLI: `--upstream-timeout` (30 s), `--max-queue` (límite de eventos pendientes de envío: 10 000),
`--preserve-host / --rewrite-host`, `--access-log`.

### Comportamientos que conviene conocer

- **Use `--trust-forwarded-for` solo detrás de un balanceador de carga de confianza**. Sin esta opción, los encabezados
  `X-Forwarded-*` enviados por el cliente se descartan y se sustituyen por los valores observados por Gate (para impedir la suplantación de la IP de origen).
- Los datos capturados **se enmascaran en Gate antes de enviarlos** (valores de encabezados como `Authorization` o `Cookie`,
  valores de parámetros como `password=`, tokens, claves, direcciones de correo electrónico, etc.).
- **fail-open**: aunque el servidor de TOKIWA se detenga, el proxy de Gate sigue funcionando (los eventos se acumulan temporalmente y se reenvían).
- **fail-static**: si no puede obtener la política, mantiene la última (para no abrir la vía de "tumbar el servidor para que se levanten los bloqueos").
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
- Entre los valores de `kind` están `http` / `port_snapshot` / `connection` / `ids_alert` / `dns` / `process` / `auth` / `deception` /
  `llm_app` / `custom`, entre otros. Para los detalles del esquema, consulte la documentación de la API del servidor (`http://<server>:8788/api/docs`).
- ⚠️ **La API de ingesta no aplica enmascaramiento en el servidor** (Gate y Agent enmascaran antes de enviar).
  Si envía datos directamente, no incluya secretos como contraseñas o tokens. Aun así, los datos siempre se enmascaran justo antes de pasarlos al LLM.

Los chats HTTP en JSON (por defecto, dirigidos a `/api/chat`, `/v1/chat/completions` y `/chat`) pasan automáticamente a ser objeto
de la detección de inyección de prompts si atraviesan Gate (puede cambiarse con `detection.llm_app_paths`).
