> 🌐 [日本語](Lab-and-Evaluation) · [English](Lab-and-Evaluation-en) · [中文](Lab-and-Evaluation-zh) · **Español**

# Laboratorio y evaluación

TOKIWA incluye un **entorno de laboratorio**, un **simulador de tráfico de ataque** y un **arnés de evaluación** para probar la detección.
Además, se ofrece el procedimiento para un **ejercicio de purple team** contra ARTEX, del lado atacante.

> ⚠️ Dirija el simulador y ARTEX **solo contra objetivos que usted administre y para los que tenga autorización de pruebas**.

## Estructura del laboratorio

```
 Simulador / ARTEX ──▶ Gate :8080 (captura + bloqueo) ──▶ Aplicación víctima :3000 (tienda de demostración; sin vulnerabilidades)
                          │
                          ▼
                   TOKIWA :8788 (API + UI) ◀── Agent (opcional: logs JSON de nginx / host)
```

La **aplicación víctima** (`lab/victim/app.py`) parece una tienda de demostración con inicio de sesión, búsqueda, API de productos, chat (`/api/chat`), OpenAPI, etc.,
pero **en realidad no es vulnerable**. No tiene base de datos, ni lectura de archivos, ni shell, y todas las respuestas son fijas.
No obstante, para provocar la "adaptación tras errores" de los agentes de IA, devuelve errores verosímiles
(número impar de comillas → 500 con aspecto de error SQL, `<script` → 403 con aspecto de WAF, etc.). La página principal contiene un canario de IA para el laboratorio
(se desactiva con `LAB_AI_CANARY=0`).

### Ejecutar sin Docker (verificado)

Es el procedimiento de "3. Montar un minilaboratorio y lanzar ataques" de [Inicio rápido](Quick-Start-es).

### Ejecutar con Docker Compose

```bash
docker compose -f lab/compose.yaml up --build -d            # tokiwa + gate + victim
# Abra http://localhost:8788 y, la primera vez, cree el administrador

docker compose -f lab/compose.yaml --profile sim run --rm sim                          # Mezcla por defecto
SIM_PROFILE=ai_agent docker compose -f lab/compose.yaml --profile sim run --rm sim     # Solo agentes de IA
SIM_PROFILE=ai_agent=2,benign_browser=4 SIM_TIME_SCALE=0.2 docker compose -f lab/compose.yaml --profile sim run --rm sim
docker compose -f lab/compose.yaml --profile ingest run --rm sim-ingest                # Envío directo sin pasar por Gate
docker compose -f lab/compose.yaml --profile agent up -d                               # nginx(:8081) + agent
docker compose -f lab/compose.yaml down                                                # Detener (con -v también se borran los datos)
```

Para ejecutarlo con un LLM real, arránquelo añadiendo variables como `TOKIWA_LLM_PROVIDER=auto ANTHROPIC_API_KEY=... TOKIWA_LLM_BUDGET_USD=2`
(el presupuesto diario por defecto del laboratorio es de $1).

> ✅ **Verificado (2026-11-10, auditoría L14, en un sandbox; no se registraron las versiones de Docker / Compose)**: con `up -d`,
> `tokiwa-init` termina correctamente y `tokiwa` / `gate` / `victim` quedan healthy; configuración inicial en la UI; y desde el `sim`
> de `--profile sim`: alertas → incidente → propuesta de respuesta → aprobación → bloqueo en el Gate (403). El bloqueo tardó unos
> 4–8 segundos en aplicarse tras la aprobación.
>
> ⚠️ En ese entorno, un `up --build` directo falló por el límite de peticiones de Docker Hub (429), un 403 de ghcr.io y un proxy que
> intercepta TLS. El laboratorio se arrancó tras sustituir las imágenes base mediante argumentos de compilación (`NODE_IMAGE` /
> `PYTHON_IMAGE` / `UV_IMAGE`) y reetiquetar a mano la imagen base del victim (detalles en "検証状況" de `lab/README.md`).
> **Sin verificar**: `--profile ingest` y `--profile agent`, y la ejecución con un LLM real.

## Simulador (`tokiwa sim`)

| Perfil | Etiqueta de referencia | Comportamiento |
|---|---|---|
| `benign_browser` | Legítimo | Usuario normal que compra con el navegador |
| `scanner` | Escáner automatizado | Escaneo mecánico con listas de palabras + firmas (velocidad constante) |
| `human_attacker` | Humano | Prueba SQLi / XSS a mano, a ritmo humano |
| `ai_agent` | Agente de IA | Agente autónomo como ARTEX (descubrimiento de API a partir de JS / OpenAPI, mutación tras errores, ráfagas y esperas de razonamiento, obediencia a canarios) |
| `llm_app_attacker` | Humano | Inyección de prompts y jailbreak contra `/api/chat` |
| `api_only_agent` | Agente de IA (reservado) | Un bucle de herramientas de LLM que solo llama a la API (empieza por OpenAPI, nunca toca HTML, robots ni canarios, una petición por turno, UA de cliente HTTP genérico) |
| `slow_rotating_agent` | Agente de IA (reservado) | Un agente que maneja un navegador (cabeceras completas de Chrome), pausas de razonamiento con una mediana de unos 20 segundos, IP de origen que cambia cada pocas peticiones |

Los **perfiles reservados (holdout)** tienen formas que no se usaron para diseñar ni ajustar los detectores, y no están en la mezcla por defecto. Indíquelos explícitamente (`--profile api_only_agent=2,...`) o inclúyalos con `--profile all --sessions N`. Los resultados de la evaluación los muestran aparte de los perfiles guionizados. La rotación de IP solo es visible para el Gate con `--spoof-xff`.

```bash
cd backend
uv run tokiwa sim profiles
uv run tokiwa sim run --profile ai_agent --target http://localhost:8080
uv run tokiwa sim run --profile ai_agent=2,benign_browser=5 --seed 7 --record ../eval/datasets/live.jsonl
```

Restricciones de seguridad:

- Los destinos se limitan a localhost, IP privadas y nombres que se resuelvan a ellas. Cualquier otro se rechaza salvo que se añada `--i-own-this-target`
  (úselo solo con objetivos de su propiedad y para los que tenga autorización de pruebas).
- No sigue redirecciones ni usa las variables de entorno de proxy. Hay límites para el número total de solicitudes (2000 por defecto) y para la velocidad (50 rps por defecto).
- Las cargas útiles son cadenas inofensivas para pruebas de detección (las referencias externas usan dominios `.invalid`).

## Arnés de evaluación (`tokiwa eval`)

Pasa un dataset etiquetado por el procesamiento de TOKIWA (ingesta → detección → correlación → triaje) y calcula métricas.
La evaluación se realiza en una base de datos desechable, por lo que no afecta al servidor en funcionamiento. Las etiquetas de referencia no se muestran ni a los detectores ni al LLM.

```bash
cd backend
uv run tokiwa sim generate --out ../eval/datasets/mix.jsonl                  # Generación sin conexión (con el mismo seed, el mismo archivo)
uv run tokiwa eval run --dataset ../eval/datasets/lab-mini.jsonl             # LLM simulado (gratis, sin conexión)
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --compare ../eval/runs/<anterior> --fail-on-regression
uv run tokiwa eval run --dataset ../eval/datasets/mix.jsonl --llm live --budget-usd 0.50   # LLM real (genera costos)
uv run tokiwa eval compare ../eval/runs/<actual> ../eval/runs/<anterior>
```

Los resultados se escriben en `eval/runs/<hora UTC>/` como `metrics.json` y `report.md`.

| Métrica | Significado |
|---|---|
| Tasa de detección de sesiones de ataque (medium o superior) | **Métrica principal**. Proporción de sesiones de ataque con al menos una alerta de severidad medium o superior |
| Tasa de detección de sesiones de ataque (cualquier severidad) | Métrica secundaria. Cuenta una sesión como detectada aunque solo tenga una alerta info / low |
| Tasa de falsos positivos en sesiones legítimas | Proporción de sesiones legítimas que recibieron alguna alerta |
| Precisión de las alertas | Proporción de alertas atribuidas solo a sesiones de ataque (también se calcula por detector) |
| Atribución de IA P / R / F1 / AUC | Exactitud al clasificar las sesiones según si son "un agente de IA" |
| Tasa de concordancia del LLM | Proporción de evaluaciones del triaje (tipo de actor, malicioso, IA) que coinciden con la referencia |
| Costo y latencia | Costo del LLM, latencia ingesta → alerta y alerta → triaje |

Cada tasa se informa con su numerador / denominador y un intervalo del 95% (Clopper–Pearson); los valores con menos de 30 ensayos
se muestran como **valores de referencia** (参考値) en `report.md` (el lab-mini incluido tiene 3 sesiones legítimas y 2 de IA, por lo
que "0/3 falsos positivos" tiene un intervalo de 0–70.8%). Con `--llm mock`, la "tasa de concordancia del LLM" es la evaluación
alternativa basada en reglas coincidiendo consigo misma y **no es la calidad del LLM**; el costo se muestra como el real ($0) más una
estimación aparte (tokens estimados × tabla de precios). `--compare` avisa de que dos ejecuciones "no son comparables" cuando sus
condiciones difieren (sha256 del dataset, proveedor LLM, detectores activos, número de reglas Sigma cargadas, umbrales), y entonces
`--fail-on-regression` termina con el código 3 (use `--allow-mismatch` para una comparación intencionada). También se comparan el
total de alertas y el número por detector.

> El dataset incluido (`eval/datasets/lab-mini.jsonl`) se sintetizó a partir de las mismas hipótesis que los detectores. Considere que las cifras obtenidas con él
> **serán más altas que en un entorno real**.

## Ejercicio de purple team con ARTEX

El perfil `ai_agent` del simulador no es más que un modelo hipotético, así que **la verificación que cuenta de verdad es la realizada con agentes de IA reales**.

1. Arranque el laboratorio (véase más arriba).
2. Arranque ARTEX. Por defecto, el proxy de registro de tráfico de ARTEX **usa :8788 y entra en conflicto con TOKIWA**,
   así que configure ARTEX en otro puerto (por ejemplo: `./start.sh -addr :8787 -proxy :18788`).
3. **Antes de crear la tarea**, active en la configuración del sistema de ARTEX el registro de tráfico (clave `traffic_capture`) y el
   registro del LLM (`llm_record`), y borre los registros anteriores del host objetivo. Ambos registros están desactivados por
   defecto y, si siguen así, no quedan datos para la evaluación posterior. ARTEX guarda los registros por host, no por tarea
   (detalles en `docs/purple-team.md` §2).
4. Limite el objetivo de las tareas de ARTEX **únicamente al Gate del laboratorio (`http://<host del laboratorio>:8080`)**.
5. Qué observar en TOKIWA durante el ejercicio:
   - **AI sessions** (Sesiones de IA): si las sesiones de ARTEX se clasifican como agente de IA y obtienen una puntuación alta
   - **Alerts** (Alertas): `ai.agent_session`, `ai.adaptive_mutation`, `ai.semantic_recon`, `ai.llm_client_fingerprint`, `deception.trip`, etc.
   - **Incidents** (Incidentes): si **Actor attribution** (Atribución del actor) pasa a ser agente de IA y si las fases del ataque avanzan
   - **Response** (Respuesta): si los bloqueos y demás acciones **se quedan en propuesta** y no se ejecutan hasta que se aprueban
6. Después, puede convertir los registros de ARTEX en un dataset y volver a evaluarlos tantas veces como quiera.

```bash
cd backend
uv run tokiwa eval import-artex <directorio donde se extrajo el archivo de tarea de ARTEX> --host <host del laboratorio> \
  --since <inicio del ejercicio UTC> --until <fin del ejercicio UTC> --split-gap-minutes 30 --out ../eval/datasets/artex-<fecha>.jsonl
uv run tokiwa sim generate --profile benign_browser=10 --out ../eval/datasets/benign.jsonl
cat ../eval/datasets/artex-<fecha>.jsonl ../eval/datasets/benign.jsonl > ../eval/datasets/purple-<fecha>.jsonl
uv run tokiwa eval run --dataset ../eval/datasets/purple-<fecha>.jsonl
```

`import-artex` puede leer archivos de tarea (`traffic/traffic.json`), ZIP de evidencias, índices de registros (SQLite) y volcados de la API.
Las horas de los registros de ARTEX son **horas de finalización de la respuesta con resolución de 1 segundo**, y no incluyen la IP
de origen (se completa con `--source-ip`). Los intervalos y ráfagas de los eventos importados son aproximados, así que evalúe el ritmo
de las peticiones con la captura en vivo del Gate durante el ejercicio. El orden de las cabeceras tampoco tiene significado. Puede
acotar el intervalo con `--since` / `--until` y separar sesiones en los silencios con `--split-gap-minutes`. Si no se importa nada,
el comando indica si probablemente el registro estaba desactivado, qué hosts había y qué intervalo de tiempo cubren los registros.
TOKIWA solo lee el formato de registro de ARTEX; no incluye código de ARTEX.
