> 🌐 [日本語](Configuration) · [English](Configuration-en) · [中文](Configuration-zh) · **Español**

# Referencia de configuración

## Cómo pasar la configuración y orden de prioridad

Cuanto más arriba en la lista, mayor prioridad.

1. **Variables de entorno** `TOKIWA_*` (los niveles anidados se unen con `__`; por ejemplo: `TOKIWA_LLM__DAILY_BUDGET_USD=10` → `llm.daily_budget_usd`)
2. **Archivo YAML**: la ruta indicada en `TOKIWA_CONFIG` (por defecto, `tokiwa.yaml` en el directorio actual; si no existe, se ignora)
3. **Valores por defecto** (`backend/src/tokiwa/config.py`)

Además, los dos elementos siguientes pueden **sobrescribirse en tiempo de ejecución desde la interfaz web**, y esos valores se guardan en la base de datos.

- Configuración del LLM (**LLM → Settings** (LLM → Configuración)): proveedor, modelos, presupuesto, idioma de salida, clave de API, etc.
- Activación / desactivación de detectores (**Rules → Detectors** (Reglas de detección → Detectores))

Con Docker Compose, `.env` se pasa al contenedor como variables de entorno. Si ejecuta `tokiwa serve` directamente en local,
`.env` no se carga automáticamente.

### Precauciones de escritura

- **Las listas y los diccionarios se escriben en JSON**: `TOKIWA_DETECTION__DISABLED_DETECTORS='["web.scanner_ua"]'`
- **No defina valores vacíos**. `TOKIWA_SERVER__SECRET_KEY=` se trata como "clave de firma de cadena vacía" (no es lo mismo que no definirla).
- Se recomienda pasar los secretos (claves de API, contraseñas) mediante variables de entorno y no en el YAML.

### Ejemplo de YAML

```yaml
# tokiwa.yaml
server:
  base_url: https://tokiwa.example.internal
llm:
  daily_budget_usd: 10
  output_language: ja
triage:
  min_severity_for_llm: high
response:
  protected_cidrs: ["127.0.0.0/8", "::1/128", "10.0.0.0/24"]
  default_ttl_minutes: 30
deception:
  labyrinth_enabled: true
```

## Principales opciones de configuración

### General, servidor y base de datos

| Clave | Por defecto | Descripción |
|---|---|---|
| `env` | `dev` | `dev` / `prod` / `test` |
| `log_level` | `INFO` | Nivel de log |
| `server.host` / `server.port` | `0.0.0.0` / `8788` | Dirección y puerto de escucha |
| `server.base_url` | `http://localhost:8788` | URL que abren los usuarios (enlaces de las notificaciones, etc.) |
| `server.cors_origins` | `["http://localhost:5173"]` | Solo si la interfaz se sirve desde otro origen |
| `server.static_dir` | Ninguno | Interfaz compilada (`frontend/dist`). Si se indica, se sirve en `/` |
| `server.data_dir` | `./data` | Ubicación de los datos (clave de firma, etc.) |
| `server.secret_key` | Generada automáticamente | Clave de firma del inicio de sesión (JWT). Si no se define, se genera y se guarda en `data_dir/secret.key` |
| `server.token_ttl_minutes` | 720 | Tiempo de validez de la sesión iniciada |
| `database.url` | `sqlite+aiosqlite:///./data/tokiwa.db` | Para PostgreSQL, `postgresql+asyncpg://user:pass@host/db` |

### LLM (`llm.*`)

Consulte [Configuración de LLM y costos](LLM-es). Principales: `provider`, `anthropic_api_key` (o la variable de entorno `ANTHROPIC_API_KEY`),
`openai_base_url` / `openai_api_key`, `model_fast` / `model_deep`, `daily_budget_usd`, `output_language`, `redaction.*`.

### Detección (`detection.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `disabled_detectors` | `[]` | ID de los detectores que se desactivan |
| `sigma_rule_dirs` | `["../rules/sigma"]` | Ubicación de las reglas Sigma |
| `dedup_window_seconds` | 300 | Ventana de tiempo para agrupar alertas idénticas |
| `llm_app_paths` | `/api/chat`, `/v1/chat/completions`, `/chat` | Rutas HTTP supervisadas para detectar inyección de prompts |
| `session_idle_timeout_seconds` | 1800 | Si no hay accesos durante este tiempo, se considera una sesión distinta |
| `ai_agent_threshold` | 0.7 | Umbral de puntuación de IA para clasificar como agente de IA |
| `web.*` | — | Umbrales de las detecciones por tasa en tráfico web (ráfagas de errores, fallos de inicio de sesión, inundaciones, etc.) |

### Triaje y correlación (`triage.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `auto_triage` | true | Triaje automático de las alertas con el LLM |
| `min_severity_for_llm` | `medium` | Severidad mínima para enviar al LLM |
| `escalate_confidence_below` | 0.6 | Si la confianza del modelo rápido es inferior a este valor, se pasa al modelo profundo |
| `escalate_severity` | `high` | A partir de esta severidad, se usa el modelo profundo |
| `max_concurrent` | 4 | Número de triajes simultáneos |
| `incident_window_minutes` | 60 | Ventana de tiempo para agrupar alertas en un mismo incidente |
| `max_evidence_events` | 25 | Número máximo de eventos de evidencia que se pasan al LLM |

### Acciones de respuesta (`response.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `auto_approve_enabled` / `auto_approve_actions` | false / `[]` | Aprobación automática (requiere ambos ajustes) |
| `default_ttl_minutes` / `max_ttl_minutes` | 60 / 10080 | TTL por defecto y máximo |
| `protected_cidrs` | `127.0.0.0/8`, `::1/128` | Rangos que nunca serán objetivo |
| `protect_server_addresses` | true | Protege las IP del propio servidor |
| `block_private_targets` | false | Prohíbe usar direcciones privadas como objetivo (protección de la red de administración) |
| `default_rate_limit_rpm` / `default_tarpit_delay_ms` | 60 / 2000 | Valores por defecto de la limitación de tasa y del tarpit |
| `nftables_enabled` | false | Bloqueo mediante nftables |
| `webhook_urls` / `webhook_allowed_hosts` / `webhook_block_private` | `{}` / `[]` / true | Destinos de los webhooks como acción de respuesta y protección contra SSRF |

### Engaño (`deception.*`) e inteligencia (`intel.*`)

Consulte [Engaño (Mirage)](Deception-es) e [Inteligencia de vulnerabilidades](Threat-Intel-es).

### Gate (`gate.*`) y Agent (`agent.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `gate.upstream` | `http://127.0.0.1:3000` | Destino del reenvío |
| `gate.listen_host` / `gate.listen_port` | `0.0.0.0` / 8080 | Dirección y puerto de escucha |
| `gate.server_url` | `http://127.0.0.1:8788` | Servidor de TOKIWA |
| `gate.ingest_token` | Ninguno | Token de API (ámbito: ingest + gate) |
| `gate.capture_body_bytes` | 4096 | Número de bytes iniciales del cuerpo que se capturan |
| `gate.trust_forwarded_for` | false | Confiar en `X-Forwarded-For` |
| `agent.server_url` | `http://127.0.0.1:8788` | Servidor de TOKIWA |
| `agent.ingest_token` | Ninguno | Token de API (ámbito: ingest) |
| `agent.interval_seconds` | 10 | Intervalo de recopilación del sensor de host |
| `agent.nginx_json_logs` / `caddy_json_logs` / `suricata_eve_logs` / `zeek_log_dirs` | `[]` | Logs que se ingieren |
| `agent.verify_tls` | true | Verificar el certificado TLS del servidor |

### Notificaciones (`notify.*`) y copiloto (`copilot.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `notify.default_webhook_url` | Ninguno | Webhook por defecto, utilizable sin registrarlo en la interfaz |
| `notify.default_min_severity` | `high` | Severidad mínima del webhook por defecto |
| `notify.public_ui_url` | Ninguno | Destino de los enlaces a la interfaz incluidos en las notificaciones |
| `notify.language` | `both` | Idioma de las notificaciones |
| `notify.dedup_minutes` | 10 | Tiempo durante el que se suprimen las notificaciones idénticas |
| `notify.allowed_hosts` / `notify.block_private_destinations` | `[]` / true | Restricción de destinos (protección contra SSRF) |
| `copilot.enabled` | true | Copiloto |
| `copilot.tier` | `deep` | Nivel (tier) del modelo que se usa |
| `copilot.max_tool_iterations` | 8 | Número máximo de usos de herramientas por pregunta |

Todas las opciones están en `backend/src/tokiwa/config.py`. Para un ejemplo para Docker, consulte `.env.example` en la raíz del repositorio.
