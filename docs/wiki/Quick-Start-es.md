> 🌐 [日本語](Quick-Start) · [English](Quick-Start-en) · [中文](Quick-Start-zh) · **Español**

# Inicio rápido

Este procedimiento arranca TOKIWA en su propia máquina y, con el simulador de ataques incluido, recorre el ciclo completo
"detectar un ataque de un agente de IA → aprobación humana → bloqueo". No se usa Docker. Lleva unos 10–15 minutos.

> Para una configuración de uso habitual cercana a producción (Docker Compose), consulte [Instalación y operación](Installation-es).

## Requisitos

| Software | Versión | Uso |
|---|---|---|
| Python | 3.12 o superior | Backend |
| [uv](https://docs.astral.sh/uv/) | La más reciente | Gestión de dependencias de Python |
| Node.js / npm | Serie 22 | Compilación de la interfaz web |
| git | — | Obtención del código |

El funcionamiento se ha comprobado en Linux. Se espera que en macOS funcione con los mismos pasos, pero aún no está verificado. Windows aún no está verificado.
**Funciona sin** clave de API de LLM (en ese caso utiliza un LLM simulado —mock— y la evaluación basada en reglas).

## 1. Obtención e instalación

```bash
git clone https://github.com/JUCK-Kurohasu/TOKIWA.git
cd TOKIWA

cd frontend && npm install && npm run build && cd ..   # Compila la interfaz web (frontend/dist)
cd backend && uv sync                                   # Instala las dependencias del backend
```

## 2. Arrancar el servidor

```bash
# Ejecutar en backend/
TOKIWA_SERVER__STATIC_DIR=../frontend/dist uv run tokiwa serve
```

Abra <http://localhost:8788> en el navegador. La primera vez se muestra la página **/setup** (configuración inicial), donde se crea el primer administrador.

- Nombre de usuario: de 3 a 64 caracteres (alfanuméricos y `_` `.` `-`)
- Contraseña: 10 caracteres o más

Los datos (la base de datos SQLite y la clave de firma) se guardan en `backend/data/`.

> 💡 Si va a modificar la interfaz mientras la usa, ejecute `make dev` en la raíz del repositorio: se arrancan a la vez la API (:8788, con recarga automática) y
> el servidor de desarrollo de la interfaz (:5173).

### Si se usa un LLM (opcional)

Antes de arrancar el servidor, pase la clave de API mediante una variable de entorno.

```bash
export ANTHROPIC_API_KEY=sk-ant-...      # Al definirla, el proveedor pasa a ser Anthropic automáticamente
```

El presupuesto diario por defecto es de **$5**. Lo que lo exceda pasa a la evaluación basada en reglas. Para más detalles, consulte [Configuración de LLM y costos](LLM-es).

## 3. Montar un minilaboratorio y lanzar ataques

Se coloca TOKIWA Gate delante de la aplicación de demostración "víctima" incluida y se envía tráfico de ataque con el simulador.
Se usan **3 terminales** (4 en total, contando la del servidor).

```
 Simulador ──▶ Gate :8080 ──▶ Aplicación víctima :3000 (tienda de demostración sin vulnerabilidades)
                 │
                 ▼
         TOKIWA Server :8788
```

**Terminal A — aplicación víctima** (todas las respuestas son fijas; en realidad no es vulnerable)

```bash
cd lab/victim
../../backend/.venv/bin/uvicorn app:app --host 127.0.0.1 --port 3000
```

**Terminal B — crear un token de API para Gate y arrancar Gate**

```bash
cd backend
uv run tokiwa token create gate-1        # tkw_... se muestra una sola vez; anótelo
export TOKIWA_GATE__INGEST_TOKEN=tkw_...  # Más seguro que un argumento de línea de comandos (no aparece en ps)
uv run tokiwa gate run --upstream http://127.0.0.1:3000 --listen 127.0.0.1:8080 \
  --server http://127.0.0.1:8788 --trust-forwarded-for
```

> ⚠️ Ejecute `tokiwa token create` en **el mismo directorio (`backend/`) y con las mismas variables de entorno** que el servidor.
> La ubicación de la base de datos (por defecto `./data/tokiwa.db`) es una ruta relativa al directorio actual en el momento de la ejecución.

`--trust-forwarded-for` es un ajuste exclusivo del laboratorio para que el simulador declare su IP de origen mediante `X-Forwarded-For`.
En producción, no lo use salvo "cuando se encuentre detrás de un balanceador de carga de confianza".

**Terminal C — lanzar ataques con el simulador**

```bash
cd backend
uv run tokiwa sim run --target http://127.0.0.1:8080 --time-scale 0.1 --spread 10 --spoof-xff
```

Se envía tráfico que mezcla 5 tipos: usuarios legítimos, escáneres, atacantes humanos, agentes de IA y atacantes de aplicaciones LLM
(termina en unos minutos). Los destinos se limitan a direcciones locales/privadas, y las cargas útiles son solo cadenas inofensivas para pruebas de detección.

> `--time-scale 0.1` reduce los tiempos de espera a 1/10 para terminar antes. Como el "ritmo" de las solicitudes deja de ser el real,
> omítalo si quiere examinar la clasificación con rigor (por defecto 1.0).

## 4. Ver los resultados

Abra las siguientes páginas en la interfaz web.

| Página | Qué observar |
|---|---|
| **Dashboard** (Panel) | Número de alertas, incidentes abiertos, número de sesiones de IA y acciones de respuesta pendientes de aprobación |
| **AI sessions** (Sesiones de IA) | Puntuación de IA por origen. Las sesiones de agentes de IA aparecen en las primeras posiciones, marcadas en morado como **AI agent** (agente de IA) |
| **Incidents** (Incidentes) | Las alertas de un mismo origen se agrupan, con la fase del ataque (reconocimiento → acceso inicial, etc.) y el resultado del triaje del LLM |
| **Alerts** (Alertas) | Detecciones individuales (inyección SQL, escáneres, accesos a señuelos, obediencia a canarios de IA, etc.) |

## 5. Aprobar y bloquear

1. Abra la pestaña **Awaiting approval** (Pendientes de aprobación) de la página **Response** (Respuesta). Allí aparecen las acciones propuestas por el LLM (o por las reglas), como `block_ip`.
2. Apruebe con **Approve** (Aprobar) el `block_ip` dirigido a la IP de origen del agente de IA.
3. En pocos segundos (el intervalo de obtención de políticas de Gate es de 5 s por defecto), Gate empieza a devolver **403** a las solicitudes de esa IP.

```bash
# Comprobación tras la aprobación (<IP> es el origen aprobado)
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: <IP>" http://127.0.0.1:8080/   # → 403
curl -s -o /dev/null -w "%{http_code}\n" -H "X-Forwarded-For: 192.0.2.1" http://127.0.0.1:8080/  # → 200 (las demás IP pasan)
```

4. Si pulsa **Revert** (Revertir) desde la pestaña **Active** (Activas), se levanta el bloqueo (aunque no haga nada, caduca automáticamente al cumplirse el TTL, 60 minutos por defecto).

Mientras no se aprueben, las acciones de respuesta propuestas **no se ejecutan en absoluto**.

## 6. Limpieza

Detenga los procesos pulsando Ctrl-C en cada terminal. Para borrar los datos y empezar desde cero, elimine `backend/data/`.

## Siguientes lecturas

- Proteger sus propias aplicaciones: [Conexión de sensores](Sensors-es)
- Cómo leer las pantallas en detalle: [Guía de la interfaz web](Web-UI-es)
- Configuración de uso habitual: [Instalación y operación](Installation-es)
