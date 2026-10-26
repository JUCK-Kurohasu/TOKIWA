> 🌐 [日本語](CLI) · [English](CLI-en) · [中文](CLI-zh) · **Español**

# Referencia de la CLI

Todas las operaciones se realizan con el comando `tokiwa`. Si se usa desde el código fuente, `uv run tokiwa ...` en el directorio `backend/`;
en la imagen Docker, `tokiwa ...` (o el nombre del subcomando como argumento del contenedor).
Las opciones actualizadas de cada comando pueden consultarse con `--help`.

| Comando | Descripción |
|---|---|
| `tokiwa version` | Muestra la versión |
| `tokiwa serve` | Servidor (API, interfaz, ingesta, trabajos en segundo plano) |
| `tokiwa user` | Gestión de usuarios |
| `tokiwa token` | Tokens de API para sensores |
| `tokiwa gate` | Sensor de tipo proxy inverso |
| `tokiwa agent` | Sensor de host y reenvío de logs |
| `tokiwa intel` | Feeds de vulnerabilidades |
| `tokiwa sim` | Simulador de tráfico para el laboratorio |
| `tokiwa eval` | Arnés de evaluación |

> ⚠️ Ejecute los comandos que acceden directamente a la base de datos (`user`, `token`, `intel`, etc.) con **la misma configuración** que el servidor (el mismo directorio actual
> o el mismo `TOKIWA_DATABASE__URL`). La ruta por defecto de la base de datos, `./data/tokiwa.db`, es relativa.

## tokiwa serve

```bash
tokiwa serve [--host HOST] [--port 8788] [--reload] [--no-jobs]
```

| Opción | Descripción |
|---|---|
| `--host` / `--port` | Escucha (por defecto, el valor de la configuración; puerto 8788) |
| `--reload` | Reinicio automático al cambiar el código (para desarrollo) |
| `--no-jobs` | No inicia los trabajos periódicos (sincronización de inteligencia, procesamiento de vencimientos, etc.) |

La documentación de la API está en `http://<server>:8788/api/docs` y la comprobación de estado, en `/api/v1/health`.

## tokiwa user create

```bash
tokiwa user create <username> [--role admin|analyst|viewer]
```

La contraseña se solicita de forma interactiva (dos veces, con la entrada oculta). El rol por defecto es `analyst`.

## tokiwa token create

```bash
tokiwa token create <name> [--scope ingest] [--scope gate]
```

Los ámbitos por defecto son `ingest` y `gate`. El token (`tkw_...`) se muestra **una sola vez**.

## tokiwa gate run

```bash
tokiwa gate run --upstream http://127.0.0.1:3000 [--listen 0.0.0.0:8080] [--server http://127.0.0.1:8788] \
  [--token-file PATH] [--trust-forwarded-for] ...
```

| Opción | Por defecto | Descripción |
|---|---|---|
| `--upstream` | Valor de la configuración | URL de destino del reenvío |
| `--listen` | `0.0.0.0:8080` | `host:port` de escucha |
| `--server` | Valor de la configuración | URL del servidor de TOKIWA |
| `--token` / `--token-file` | — | Token de API (se recomienda la variable de entorno `TOKIWA_GATE__INGEST_TOKEN` o un archivo) |
| `--sensor-id` | `gate-1` | ID del sensor que se registra en los eventos |
| `--capture-body-bytes` | 4096 | Número de bytes iniciales del cuerpo que se capturan |
| `--trust-forwarded-for` | off | Toma el valor más a la derecha de `X-Forwarded-For` como origen (solo detrás de un balanceador de carga de confianza) |
| `--policy-refresh` | 5 | Intervalo de obtención de la política (segundos) |
| `--batch-size` / `--flush-interval` | 100 / 1.0 | Lotes de envío |
| `--upstream-timeout` | 30 | Tiempo de espera de lectura/escritura con el upstream (segundos) |
| `--max-queue` | 10000 | Límite de eventos pendientes de envío (si se supera, se descartan los más antiguos) |
| `--preserve-host` / `--rewrite-host` | preserve | Si el encabezado Host se envía tal cual o se reescribe con el del upstream |
| `--access-log` | off | Log de acceso de uvicorn |
| `--log-level` | Valor de la configuración | Nivel de log |

## tokiwa agent

```bash
tokiwa agent run  [--server-url URL] [--nginx PATH ...] [--caddy PATH ...] [--suricata PATH ...] [--zeek-dir PATH ...]
tokiwa agent once [--print] [--max-events 1000] ...
```

| Opción | Descripción |
|---|---|
| `--server-url` | URL del servidor de TOKIWA |
| `--token` | Token de API (se recomienda la variable de entorno `TOKIWA_AGENT__INGEST_TOKEN`) |
| `--sensor-id` | ID del sensor (por defecto, el nombre del host) |
| `--interval` | Intervalo del sensor de host (segundos) |
| `--host-sensor / --no-host-sensor` | Recopilación de puertos en escucha y conexiones |
| `--connections / --no-connections` | Notificación de nuevas conexiones TCP |
| `--nginx` / `--caddy` / `--suricata` / `--zeek-dir` | Logs que se ingieren (pueden indicarse varios) |
| `--from-beginning / --from-end` | Desde dónde se leen los logs (por defecto: desde el final) |
| `once --print` | Recopila una sola vez y muestra el JSON sin enviarlo (para comprobar el funcionamiento) |

## tokiwa intel

```bash
tokiwa intel sync [-s kev] [-s nvd]   # Ejecuta una sincronización (por defecto: todas las fuentes habilitadas)
tokiwa intel status                   # Estado de sincronización por fuente
tokiwa intel show CVE-2021-44228 [--json]   # Muestra un elemento integrado (ID de CVE / GHSA / JVNDB)
```

## tokiwa sim

```bash
tokiwa sim profiles
tokiwa sim run      [--profile mixed] [--target http://localhost:8080] [--sessions N] [--seed 1] \
                    [--time-scale 1.0] [--spread 60] [--max-requests 2000] [--max-rps 50] \
                    [--spoof-xff] [--record FILE.jsonl] [--loop] [--i-own-this-target]
tokiwa sim generate --out FILE.jsonl [--profile mixed] [--sessions N] [--seed 1] [--start ISO8601] [--spread 1800] [--no-canary]
tokiwa sim ingest   [--server http://localhost:8788] [--token-file PATH] [--profile mixed] [--batch-size 200]
```

| Subcomando | Descripción |
|---|---|
| `profiles` | Lista de perfiles |
| `run` | Envía tráfico real al objetivo del laboratorio (Gate) |
| `generate` | Genera un dataset etiquetado sin usar la red (con el mismo seed, el mismo archivo) |
| `ingest` | Envía eventos sintéticos directamente a la API de ingesta (no requiere Gate) |

`--profile` se indica como `ai_agent`, `ai_agent,scanner`, `ai_agent=2,benign_browser=5` o `mixed`.
Con `--time-scale` inferior a 1 termina antes, pero cambia el ritmo de las solicitudes, lo que también afecta a las características usadas en la clasificación de IA.

## tokiwa eval

```bash
tokiwa eval run --dataset FILE.jsonl [--llm mock|live] [--budget-usd N] [--out DIR] \
                [--compare PREV] [--fail-on-regression] [--speed 0] [--json]
tokiwa eval compare <current> <previous> [--fail-on-regression]
tokiwa eval import-artex <source> --out FILE.jsonl [--host HOST] [--session LABEL] [--source-ip IP]
tokiwa eval info FILE.jsonl
```

| Opción | Descripción |
|---|---|
| `--llm` | `mock` (gratis, sin conexión; por defecto) o `live` (el proveedor configurado; **genera costos**) |
| `--budget-usd` | **Obligatorio** con `--llm live`. Límite de costo de esta ejecución |
| `--out` | Destino de salida (por defecto `eval/runs/<hora UTC>`) |
| `--compare` / `--fail-on-regression` | Comparación con la ejecución anterior / código de salida 1 si hay empeoramiento |
| `--speed` | 0 = lo más rápido posible, 1 = tiempo real, 10 = 10 veces más rápido |
| `--enable-detector` / `--disable-detector` | Fuerza la activación / desactivación de un detector |
| `--keep-work` | Conserva la base de datos temporal de la evaluación |
