> 🌐 [日本語](Troubleshooting) · [English](Troubleshooting-en) · [中文](Troubleshooting-zh) · **Español**

# Solución de problemas

## Arranque e inicio de sesión

**Al abrirlo en el navegador da 404 / solo se ve la API**
La interfaz no está compilada o no se ha configurado desde dónde servirla. Tras `cd frontend && npm run build`,
arranque el servidor con `TOKIWA_SERVER__STATIC_DIR=../frontend/dist`. Durante el desarrollo también puede usar `make dev` (la interfaz en :5173).
En la imagen Docker, compruebe que no haya sobrescrito `TOKIWA_SERVER__STATIC_DIR` (por defecto `/app/frontend/dist`).

**Ha olvidado la contraseña del administrador**
Con la misma configuración que el servidor, ejecute `uv run tokiwa user create <nuevo nombre> --role admin` para crear otro administrador
y cambie la contraseña de la cuenta original con **Reset password** (Restablecer contraseña) en **Settings → Users** (Configuración → Usuarios).

**La sesión se cerró al reiniciar**
Es posible que se haya perdido la clave de firma (`data/secret.key`). Compruebe que el directorio de datos sea persistente.

## Sensores e ingesta

**Los eventos no llegan aunque el tráfico pasa por Gate**
1. Compruebe en el log de Gate si hay errores 401 / 403 en la ingesta (token incorrecto, ámbito insuficiente, token revocado).
   El token necesita los dos ámbitos, `ingest` y `gate`.
2. Compruebe que `--server` sea una URL desde la que se alcance el servidor de TOKIWA.
3. Si ejecuta `curl http://127.0.0.1:8080/__tokiwa/health` desde el host donde se ejecuta Gate, puede ver las estadísticas de envío
   (enviados, descartados, etc.).

**El token creado con `tokiwa token create` da "invalid token"**
Es posible que el comando y el servidor estén usando bases de datos distintas. La ruta por defecto de la base de datos (`./data/tokiwa.db`) es relativa,
así que ejecute el comando en el mismo directorio que el servidor (`backend/`) y con las mismas variables de entorno. Con Docker, use
`docker compose ... exec tokiwa tokiwa token create ...`.

**Todos los accesos parecen venir de la misma IP (la del balanceador de carga)**
Si Gate está detrás de un balanceador de carga, configure `--trust-forwarded-for` (`TOKIWA_GATE__TRUST_FORWARDED_FOR=true`).
Úselo **solo detrás de un balanceador de carga de confianza**. En otros entornos, permitiría suplantar la IP de origen.

**WebSocket ha dejado de funcionar**
Gate v0.1 no admite WebSocket (devuelve 501). Enrute las rutas de WebSocket sin pasar por Gate.

## Acciones de respuesta

**Se aprobó, pero no se bloquea**
- El intervalo con el que Gate obtiene la política es de 5 segundos por defecto. Espere un poco y vuelva a comprobarlo.
- Compruebe que el estado de la acción de respuesta no sea `failed`. Si se solapa con los objetivos protegidos (`response.protected_cidrs`) o con las IP del propio servidor,
  falla en la revalidación que se hace justo antes de la ejecución.
- Compruebe que la IP bloqueada coincida con la IP de origen que ve Gate (si está detrás de un balanceador de carga, consulte el punto anterior).

**Hay demasiadas acciones de respuesta pendientes de aprobación**
Las propuestas del mismo tipo y para el mismo objetivo se agrupan en una sola, pero se crea una por cada origen. Suba la severidad mínima que se envía al LLM
(`triage.min_severity_for_llm`) o rechace las propuestas claramente innecesarias. Los detectores con muchos falsos positivos pueden desactivarse en
**Rules → Detectors** (Reglas de detección → Detectores).

## LLM

**No se usa el LLM (las respuestas son simuladas)**
Compruebe el proveedor y su disponibilidad en **Current status** (Estado actual) de **LLM → Settings** (LLM → Configuración). Con `auto`, si no hay clave de API de Anthropic, se usa `mock`.
Compruebe si definió `ANTHROPIC_API_KEY` antes de arrancar el servidor o si introdujo la clave en la interfaz, y ejecute **Connection test** (Prueba de conexión).

**El triaje con LLM se detuvo a mitad de camino**
Es posible que se haya agotado el presupuesto diario (`llm.daily_budget_usd`, $5 por defecto). Ese día se pasa a la evaluación basada en reglas.
Compruébelo en **LLM → Usage** (LLM → Uso).

**El LLM rechazó responder (refusal)**
Los rechazos debidos a las funciones de seguridad del modelo se tratan como un comportamiento normal. Para esa alerta se recurre a la evaluación basada en reglas.
Puede comprobar el estado en **LLM → Call log** (LLM → Registro de llamadas).

## Inteligencia de vulnerabilidades

**La sincronización falla**
Se necesitan conexiones salientes desde el entorno donde se ejecuta TOKIWA hacia cada servicio (NVD, CISA, FIRST, OSV, JVN, GitHub, etc.).
Sin clave de API, NVD impone límites más estrictos a la velocidad de obtención, y GitHub también es más estable con un token.
Es posible que JVN no pueda obtenerse debido a la renovación del servicio por parte del proveedor (aún no verificado).

## Docker

**`PermissionError: /data/...` o "/data is not writable"**
El contenedor se ejecuta con uid 10001. Si usa un bind mount, cambie el propietario del directorio del host con
`sudo chown -R 10001:10001 <dir>` (con un volumen con nombre, los permisos quedan bien de forma automática).

**El contenedor queda en estado `unhealthy`**
Compruebe la causa con `docker inspect --format '{{json .State.Health}}' <container>`. En los roles sin HTTP (agent / sim),
defina `TOKIWA_HEALTHCHECK_URL=none`; en Gate, `http://127.0.0.1:8080/__tokiwa/health`.

**Las actualizaciones en tiempo real se detienen detrás de un proxy inverso**
Desactive el búfer para SSE (`/api/v1/stream`) y alargue el tiempo de espera de lectura (consulte el ejemplo de nginx en [Instalación y operación](Installation-es)).

## Datos

**Empezar desde cero**
Detenga el servidor y elimine el directorio de datos (`backend/data/` si lo ejecuta desde el código fuente; con Docker, el volumen).

**Aparecen errores después de actualizar**
v0.1 no tiene migración automática del esquema. Revise los cambios de esquema en las notas de la versión o en `HANDOFF.md` y,
si es necesario, restaure desde una copia de seguridad.

---

Si el problema persiste, abra un [Issue](https://github.com/JUCK-Kurohasu/TOKIWA/issues) indicando los comandos ejecutados, los logs (**ocultando la información secreta**) y el entorno.
