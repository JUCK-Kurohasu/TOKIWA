> 🌐 [日本語](Data-Handling) · [English](Data-Handling-en) · [中文](Data-Handling-zh) · **Español**

# Tratamiento de datos

Esta página resume **qué recibe TOKIWA, qué guarda, qué envía al exterior, cuánto tiempo lo conserva y quién puede verlo**.
Se basa en el código y los valores por defecto de la v0.1.0. Lo que no se pudo confirmar en el código se indica como "no verificado".

> ⚠️ **Puntos clave (con los valores por defecto)**
> - Gate guarda hasta los primeros 4.096 bytes del cuerpo de las solicitudes. Los secretos, las direcciones de correo y los números de tarjeta se enmascaran, pero
>   **los nombres, números de teléfono, direcciones postales, fechas de nacimiento, ID de inicio de sesión y similares no**.
> - Una vez configurada una clave de API del LLM, las alertas e incidentes de gravedad `medium` o superior **se envían automáticamente al
>   proveedor externo del LLM**, junto con extractos de sus eventos de evidencia.
> - **El borrado automático no está implementado**. Los datos guardados permanecen hasta que alguien los borre a mano.
> - Todos los roles, incluido `viewer`, pueden leer los eventos en bruto, cuerpos de solicitud incluidos.
>
> Las decisiones legales sobre el tratamiento de datos personales corresponden a la organización que implanta TOKIWA. Esta página reúne los hechos que sirven de base para esas decisiones.

## Recopilación y almacenamiento

### El enmascaramiento se hace en el sensor

- Gate y Agent enmascaran los eventos **en su propio proceso, antes** de enviarlos al servidor. Usan la configuración
  `llm.redaction.*` que se pasa a ese proceso (las claves están en [Configuración de LLM y costos](LLM-es)).
- El servidor **guarda los eventos tal como los recibe** (no vuelve a enmascararlos al ingerirlos). Cambiar `llm.redaction.*` en el
  servidor no cambia lo que se guarda de Gate / Agent.
- Los eventos que usted envíe directamente a la API de ingesta (`POST /api/v1/ingest/events`) también se guardan sin enmascarar. Enmascárelos en el lado emisor.
- Cada campo se recorta a `llm.redaction.max_field_chars` (por defecto 2.048 caracteres); los cuerpos de Gate se recortan a `gate.capture_body_bytes`.

### Qué recopila cada sensor

| Sensor (dataset) | Se guarda | Se enmascara | No se guarda |
|---|---|---|---|
| **Gate** (`gate.http`) | IP y puerto de origen / destino, método, Host, ruta, consulta, encabezados de la solicitud (los 64 primeros) y su orden, User-Agent, Referer, Content-Type, **los primeros `gate.capture_body_bytes` (por defecto 4.096) bytes de los cuerpos de texto**, tamaño del cuerpo, estado, tamaño y Content-Type de la respuesta, duración | Valores de los encabezados de `llm.redaction.sensitive_headers` (`Authorization`, `Cookie`, ...) y los elementos de "Se enmascara" más abajo | Cuerpos de respuesta, encabezados de respuesta (salvo Content-Type), cuerpos binarios (solo se registra el tamaño), encabezados a partir del 65.º |
| **Señuelos servidos por Gate** (`gate.deception`) | Un registro más con el mismo contenido HTTP (incluidos los valores escritos en un formulario de inicio de sesión señuelo) | Igual que arriba | Igual que arriba (estas solicitudes no se reenvían a la aplicación protegida) |
| **nginx / Caddy** (`nginx.access` / `caddy.access`) | IP y puerto de origen, método, Host, ruta, consulta, encabezados presentes en el log, estado, tamaño, duración, la línea de log original (`raw`, tras el enmascaramiento, hasta 4 KB) | Valores de encabezados (como arriba), valores de claves como `password`, `token`, `cookie` y los elementos de "Se enmascara" más abajo | Cuerpos de solicitud (los logs de acceso no los contienen) |
| **Zeek** (`zeek.conn` / `zeek.http` / `zeek.notice`) | Conexiones (IP, puerto, bytes, estado), HTTP (ruta, consulta, UA, Referer, estado), notices, la línea original (`raw`, hasta 4 KB) | Valores de claves como `password` y los elementos de "Se enmascara" más abajo | Logs distintos de estos tres. Además, **la columna `username` de `http.log` no se enmascara** y queda tal cual en `raw` |
| **Suricata** (`suricata.eve`) | Registros `alert` / `http` / `flow` / `dns` (IP y puerto, ruta, consulta y encabezados HTTP, nombres consultados y respuestas DNS), el registro EVE original (`raw`, hasta 4 KB) | Valores de encabezados, enmascaramiento por nombre de clave y los elementos de "Se enmascara" más abajo | Otros tipos como `tls`, `fileinfo`, `stats`. Si EVE está configurado para emitir cargas útiles (payload), pueden acabar en `raw` dentro del límite de 4 KB |
| **Sensor de host** (`host.ports` / `host.connections`) | Nombre del host, IP del host (hasta 32), SO, sockets en escucha, conexiones TCP nuevas (IP y puertos de ambos extremos) y, de sus procesos: nombre, ejecutable, línea de comandos (hasta 512 caracteres), usuario del SO | Valores del tipo `password=...` en las líneas de comandos, etc. | — (las contraseñas pasadas como argumentos simples pueden no enmascararse) |
| **API de ingesta** (directa) | Todo el contenido de los eventos enviados | **Nada** (el servidor no enmascara) | — |
| **Registros de activación del engaño** | El activo tocado, IP de origen, ID del evento, ruta, método, UA, el valor trampa (un valor falso generado por TOKIWA) y los nombres de los campos donde apareció | — | — (los registros de activación se conservan aunque se borre el activo) |

### Qué se enmascara y qué no

Los valores enmascarados se sustituyen por `[REDACTED:<tipo>]`.

| Se enmascara | No se enmascara (ejemplos) |
|---|---|
| Claves privadas, JWT, formatos de claves de API / tokens de servicios principales (Anthropic, OpenAI, AWS, GitHub, Slack, Google), credenciales `Bearer` / `Basic` | Nombres, números de teléfono, direcciones postales, fechas de nacimiento |
| Valores de 3 o más caracteres que siguen a `password=`, `token=`, `secret=`, `api_key=`, `auth=`, `session=` y similares | ID de inicio de sesión (valores de `username=` y similares), contraseñas de 2 caracteres o menos |
| Credenciales incrustadas en URL (`https://user:pass@...`) | Direcciones de correo codificadas en URL (que contienen `%40`) |
| Números de tarjeta que superan la comprobación de Luhn | Direcciones IPv6 (`mask_ips` solo cubre IPv4) |
| Direcciones de correo electrónico (`mask_emails`, activado por defecto) | Los campos de IP de origen / destino de los eventos (no se cubren ni con `mask_ips` activado) |
| Direcciones IPv4 dentro de cadenas (`mask_ips`, desactivado por defecto) | |

### Dónde se copian los datos dentro del servidor

Los mismos datos personales se copian en varias tablas durante la detección y el triaje. Al atender una solicitud de borrado o de acceso hay que revisar todas las siguientes.

| Tabla | Elementos que pueden contener datos personales |
|---|---|
| `events` | El evento completo (el contenido de la tabla anterior, incluido `raw`) |
| `alerts` | IP de origen, título, `entities` (ruta, Host, nombre de parámetro), el fragmento coincidente en `details` (hasta 200 caracteres en las detecciones web), resultado del triaje |
| `incidents` | Lista de IP de origen, el resumen escrito por el LLM (hasta 4.000 caracteres), resultado del triaje |
| `actor_sessions` | IP de origen, User-Agent, características de comportamiento |
| `llm_calls` | La entrada pasada al LLM (enmascarada, hasta 100.000 caracteres) y la respuesta. Se registra incluso si el proveedor es `mock` |
| `copilot_messages` | Conversaciones con el Copilot (Copiloto) y resultados de sus herramientas (incluidos los primeros 300 caracteres de los cuerpos de eventos, etc.) |
| `deception_trips` | Los registros de activación descritos arriba |
| `response_actions` | IP objetivo de las acciones de respuesta y el motivo (incluido texto escrito por el LLM) |
| `audit_log` | Nombre del usuario que actuó, objetivo, detalles |
| `users` | Nombres de usuario de TOKIWA, hashes de contraseña, hora del último inicio de sesión |
| `notification_channels` | Direcciones de correo de los destinatarios, usuario SMTP, URL de webhooks |
| `settings_kv` | La clave de API del LLM introducida en la interfaz (en texto plano) |

### Recopilar menos

```bash
# Pasar al proceso de Gate
export TOKIWA_GATE__CAPTURE_BODY_BYTES=0   # no guardar cuerpos (solo se registra el tamaño); igual que --capture-body-bytes 0
# Añadir encabezados cuyo valor se oculta por completo (vuelva a listar también los 7 por defecto)
export TOKIWA_LLM__REDACTION__SENSITIVE_HEADERS='["authorization","cookie","set-cookie","proxy-authorization","x-api-key","x-auth-token","x-csrf-token","x-forwarded-user"]'

# Pasar al proceso de Agent
export TOKIWA_AGENT__CONNECTIONS=false     # no enviar conexiones TCP nuevas
export TOKIWA_AGENT__HOST_SENSOR=false     # no enviar puertos en escucha ni información de procesos
```

- Si añade `deception.canary_header` (por defecto `X-Debug-Auth`) a `sensitive_headers`, los canarios de IA dejan de detectarse.
- No incluya Cookie, Authorization ni cuerpos de solicitud en el `log_format` de nginx (véase la nota de `lab/nginx/tokiwa-json.conf`).
- Activar `mask_ips` puede afectar a la detección y a las propuestas de respuesta; pruébelo antes en un entorno de pruebas (el alcance del efecto no está verificado).
- Con `--access-log` en Gate (desactivado por defecto), el log de acceso estándar de uvicorn (dirección del cliente y línea de solicitud) se escribe en la salida estándar. Este log no pasa por el enmascaramiento de TOKIWA.

## Envío de datos al exterior

### Destinos

| Destino | Cuándo | Qué se envía | Cómo detenerlo |
|---|---|---|---|
| Proveedor del LLM: triaje automático | Al crearse una alerta de gravedad igual o superior a `triage.min_severity_for_llm` (por defecto `medium`); al crearse un incidente y cuando cambian su gravedad, etapa de ataque, etc. | Contenido de la alerta / incidente (título, descripción, IP de origen, entities), extractos de hasta `triage.max_evidence_events` (por defecto 25) eventos de evidencia, características de las sesiones de IA, vulnerabilidades relacionadas | `triage.auto_triage=false`, o no usar un proveedor externo (véase abajo) |
| LLM: triaje manual | Cuando un `analyst` o superior lo ejecuta desde la interfaz o la API (se ejecuta sin importar `auto_triage` ni la gravedad mínima) | Igual que arriba | No usar un proveedor externo |
| LLM: Copilot | Cuando un usuario hace una pregunta | La pregunta, el historial de la conversación, los resultados de las herramientas de solo lectura (ruta, consulta, UA y primeros 300 caracteres del cuerpo de eventos, alertas, incidentes, activos, etc.) | `copilot.enabled=false` |
| LLM: avisos de vulnerabilidades | Cuando se encuentra una vulnerabilidad que coincide con un activo, y de forma periódica | Información de la vulnerabilidad; nombre, tipo, criticidad y software de los activos coincidentes | `intel.enabled=false` |
| LLM: investigación web | Cada `intel.research_interval_hours` (por defecto 12) horas, solo si el proveedor no es `mock` | Temas de investigación, la lista de software de los activos (fabricante, producto, versión). La búsqueda se ejecuta en el lado del proveedor | `intel.research_enabled=false` |
| Canales de notificación (Webhook / Slack / Discord / correo) | Creación de alertas e incidentes, aumento de la gravedad de un incidente, propuestas de respuesta | Véase "Qué contienen las notificaciones" más abajo | Desactivar o borrar el canal, quitar `notify.default_webhook_url`, `notify.notify_action_proposals=false` |
| Acciones de respuesta `webhook` / `notify` | Solo cuando esa acción se aprueba | ID, tipo, IP objetivo y TTL de la acción, ID del incidente / alerta | No aprobarlas; no configurar `response.webhook_urls` |
| Fuentes de vulnerabilidades | Cada `intel.sync_interval_minutes` (por defecto 360) minutos | **Solo consultas**: un intervalo de fechas (NVD, JVN, GHSA), ID de CVE (EPSS), ecosistema, nombre de paquete y versión del software de los activos (OSV). No se envía telemetría | `intel.enabled=false`, o `intel.sources.<nombre>=false` |

### Qué evidencia se envía al LLM

En el triaje solo se extraen de cada evento de evidencia los siguientes elementos. La línea de log original (`raw`) no se envía.

- ID, hora, tipo, IP y puerto de origen / destino, nombre del host, ID de sesión, etiquetas
- HTTP: método, Host, ruta, consulta, estado, tamaños, Content-Type, algunos encabezados (13 tipos, como User-Agent, Referer, Origin,
  la familia Accept y `X-Forwarded-For`) y el orden de los encabezados, **los primeros 512 caracteres del cuerpo**
- No HTTP: el contenido del evento salvo `raw`, las etiquetas, etc. (incluidas las líneas de comandos del sensor de host)

Justo antes del envío, el servidor vuelve a enmascarar con su propio `llm.redaction.*` y envuelve los datos en un bloque de "datos no confiables".
Cuánto tiempo conserva los datos el proveedor y en qué condiciones puede usarlos depende de las condiciones de cada proveedor (TOKIWA no puede controlarlo; los detalles no están verificados).

### No enviar a un LLM externo

```bash
# Pasar al servidor
export TOKIWA_LLM__PROVIDER=mock               # no enviar nada al exterior (los veredictos vienen del mock y de las reglas)
export TOKIWA_TRIAGE__AUTO_TRIAGE=false        # no hacer ningún triaje automático (también menos registros en llm_calls)
export TOKIWA_COPILOT__ENABLED=false           # desactivar el Copilot
```

- **La configuración de la interfaz tiene prioridad sobre las variables de entorno**. Si se guardó un proveedor en **LLM → Settings**
  (LLM → Configuración), se usa ese aunque ponga `mock` en una variable de entorno. Compruebe el proveedor realmente en uso en
  «Current status» (Estado actual) de **LLM → Settings**. El enmascaramiento (`llm.redaction.*`) no se puede cambiar desde la interfaz.
- Con `mock`, el triaje sigue ejecutándose y su entrada se guarda en `llm_calls` (no se envía nada al exterior). También se registra
  la entrada de las llamadas que no se enviaron por haberse superado el presupuesto.
- Con un servidor compatible con OpenAI que funcione dentro de su organización (`llm.provider=openai_compat`), el destino queda dentro de la organización ([Configuración de LLM y costos](LLM-es)).
- Con `mask_ips=true` en el servidor, se espera que el LLM no pueda indicar una IP objetivo, por lo que no se crearían propuestas de
  bloqueo ni similares a partir del LLM (inferencia a partir del código; el comportamiento no está verificado).

### Qué contienen las notificaciones

| Notificación | Contenido |
|---|---|
| Alerta | Título (hasta 200 caracteres), descripción (hasta 600 caracteres), IP de origen, categoría, ID de regla, puntuación de IA |
| Incidente | Título, IP de origen (5 en el texto, hasta 20 en `data` del webhook), tipo de actor, puntuación de IA, número de alertas, etapa de ataque, **resumen (hasta 600 caracteres)** |
| Solicitud de aprobación de una acción | Tipo de acción, IP objetivo, TTL, proponente, **motivo (hasta 500 caracteres)** |

- No se incluyen los cuerpos, consultas ni encabezados de los eventos. Sin embargo, los títulos y descripciones de las alertas pueden contener fragmentos de cadenas controladas por el atacante, como rutas y nombres de parámetros.
- Los resúmenes de incidentes y los motivos de las acciones pueden ser texto escrito por el LLM durante el triaje. Si el LLM escribe datos personales de la evidencia, ese texto se envía tal cual al destino (con qué frecuencia ocurre con un LLM real no está verificado).
- No hay ninguna opción para elegir qué elementos se incluyen en las notificaciones.

## Conservación

- **La eliminación automática (un periodo de conservación o una purga programada) no está implementada.** Los eventos, alertas,
  incidentes, registros de llamadas al LLM, etc. permanecen hasta que alguien los borra
  ([#80](https://github.com/JUCK-Kurohasu/TOKIWA/issues/80), [#171](https://github.com/JUCK-Kurohasu/TOKIWA/issues/171)).
- Los datos de una dirección IP, una sesión de IA o todo lo anterior a una fecha se pueden borrar con la CLI `tokiwa data purge` (ver «Atención de solicitudes de los interesados» más abajo).
- Desde la UI y la API solo se pueden borrar usuarios, tokens de API, reglas, activos, activos de engaño, conversaciones del copiloto,
  líneas base de puertos y canales de notificación.
- Al borrar una conversación del copiloto se conservan los registros de llamadas al LLM (`llm_calls`) hechas en ella. Al borrar un activo de engaño se conservan sus registros de activación.
- Mientras no pueden llegar al servidor, Gate y Agent acumulan eventos **en memoria** (Gate hasta 10.000 por defecto, Agent hasta 50.000; no se escribe nada en disco).
- Los datos están en la base de datos de `database.url` (por defecto `./data/tokiwa.db`). Los archivos SQLite y directorios de datos nuevos que crea
  TOKIWA son solo del propietario (0600 / 0700), igual que la clave de firma de inicio de sesión `secret.key`; los archivos y directorios
  existentes no se modifican. Las copias de seguridad de la base de datos contienen los mismos datos.

## Quién puede verlo

### Por rol (permisos de la API)

La tabla de roles de la [guía de la interfaz web](Web-UI-es) describe qué operaciones puede hacer cada rol. Qué datos puede leer cada rol
lo deciden los permisos de la API indicados abajo (lo que la UI no muestra también se puede obtener por la API).

| Datos | `viewer` | `analyst` | `admin` |
|---|:-:|:-:|:-:|
| Eventos en bruto (cuerpo, query, valores de cabeceras, `raw`, líneas de comando de procesos del host) | enmascarado¹ | ✅ | ✅ |
| Origen, destino, método, host, ruta, estado y User-Agent del evento | ✅ | ✅ | ✅ |
| Sesiones de IA (IP de origen, User-Agent; sus eventos siguen la primera fila) | ✅ | ✅ | ✅ |
| Alertas (incluido el texto coincidente de `details`; los eventos de evidencia siguen la primera fila), incidentes (resumen, resultado del triaje) | ✅ | ✅ | ✅ |
| Registros de activación de engaño (valor del token enmascarado para viewer), acciones de respuesta (IP objetivo, motivo) | ✅ | ✅ | ✅ |
| Lista de llamadas al LLM (uso, coste, estado; sin el texto de entrada ni de respuesta²) | ✅ | ✅ | ✅ |
| Usar el copiloto (sus herramientas pueden buscar eventos, etc.) | —³ | ✅ | ✅ |
| Texto de entrada y respuesta de las llamadas al LLM | — | — | ✅ |
| Conversaciones del copiloto de otros usuarios, registro de lecturas (`GET /api/v1/audit/access`) | — | — | ✅ |
| Registro de auditoría, lista de usuarios, configuración de canales de notificación | — | — | ✅ |

- ¹ Para `viewer`, la query, el cuerpo, los valores de cabeceras (salvo User-Agent, Host, Content-Type, Accept y Content-Length), la parte
  de query del Referrer, `raw`, las líneas de log de sensores distintos de Gate, las líneas de comando y los prompts de aplicaciones LLM se
  sustituyen por `[redacted: analyst role required]`. Las rutas siguen visibles (cuidado si la aplicación pone datos personales en las rutas).
- ² En un chat rechazado, el campo `error` de la lista contiene los primeros 500 caracteres de la salida del modelo.
- ³ Por defecto `copilot.min_role: analyst`; con `viewer` también pueden usarlo los viewers. Cada usuario puede enviar hasta `copilot.messages_per_minute` mensajes por minuto (6 por defecto).
- El flujo en directo (`GET /api/v1/stream`) envía a todos los usuarios con sesión iniciada el contenido de alertas (incluido `details`),
  incidentes y acciones de respuesta, y las activaciones de engaño (IP de origen). De los eventos solo se envía el número; no se envían entradas ni respuestas del LLM.
- **Registro de lecturas**: las listas y detalles de eventos y sesiones de IA, los detalles de llamadas al LLM y las ejecuciones de herramientas
  del copiloto se registran en `access_log` (quién, qué vista, qué filtro, cuántas filas; las lecturas repetidas del mismo usuario con el mismo
  filtro se agrupan en una fila cada 5 minutos). Los inicios de sesión correctos y fallidos, los cierres de sesión y la configuración inicial
  van al registro de auditoría. La consulta de alertas e incidentes no se registra.

### Quién puede verlo fuera de TOKIWA

- Quien pueda leer el archivo de la base de datos y sus copias de seguridad (usuarios del SO, administradores de copias de seguridad)
- El proveedor del LLM (en lo que se le envió)
- Los destinos de notificación (Slack, Discord, servidores de correo, receptores de webhooks) y los miembros de esos canales
- Los administradores de los hosts donde se ejecutan Gate / Agent (mientras los eventos están en memoria antes del envío)

## Atención de solicitudes de los interesados

Los datos de una dirección IP, una sesión de IA o un intervalo de tiempo se pueden exportar y borrar con la CLI en el host del servidor (no hay UI ni API para ello).

- **Buscar**: los eventos se filtran por IP de origen (`GET /api/v1/events?source_ip=...`) o por una subcadena de la ruta o el User-Agent (`q=`).
  Ninguna API busca dentro de cuerpos o queries.
- **Exportar**: `tokiwa data export --ip 203.0.113.7 --out subject.jsonl` (`--session` / `--before` también acotan; el archivo de salida es 0600).
- **Borrar**: `tokiwa data purge --ip 203.0.113.7` solo muestra cuántas filas se borrarían (dry run). Añada `--yes` para borrar.
  - Los eventos, las sesiones de IA y los registros de activación de engaño se borran fila a fila.
  - Las alertas conservan la fila; solo se vacía `details`.
  - `llm_calls` conserva el registro de coste; solo se vacían los textos de entrada y respuesta (filas cuyo texto contiene la IP como palabra y filas de alertas relacionadas).
  - La exportación y la purga (incluido el dry run) quedan en el registro de auditoría como `data.export` / `data.purge`.
- **Lo que esto no elimina**: no hay búsqueda ni borrado por identificadores distintos de la IP (como IDs de inicio de sesión). Los resúmenes de
  incidentes, el historial de notificaciones, las copias de seguridad de la base de datos y lo que los usuarios hayan guardado por su cuenta quedan
  fuera. Si hace falta, revise la base de datos directamente (ver «Dónde se copian los datos dentro del servidor» arriba), y detenga el servidor y
  haga una copia de seguridad antes de editarla a mano.
- **Lo enviado al exterior**: lo enviado al proveedor del LLM o a los destinos de notificación no se puede recuperar desde TOKIWA.

## Aspectos que el operador debe revisar

Qué leyes y normas se aplican y qué exigen debe determinarlo la organización que implanta TOKIWA, con ayuda de expertos cuando sea necesario.
Lo siguiente es una lista de aspectos generales y no es exhaustiva.

- **Finalidad del uso**: ¿hay que especificar, notificar o publicar que los datos de los usuarios de la aplicación protegida (entradas de formularios, direcciones IP, etc.) se usan para la monitorización de seguridad?
- **Recopilación mínima**: ¿es necesario guardar los cuerpos (`gate.capture_body_bytes`)? ¿Hay elementos innecesarios en los formatos de log o en los encabezados?
- **Comunicación a terceros**: ¿el envío al proveedor del LLM o a los servicios de notificación constituye un encargo de tratamiento, una comunicación a terceros o una transferencia internacional? ¿Cuáles son los plazos de conservación y las condiciones de uso secundario de los destinatarios?
- **Plazo de conservación**: cuántos días conservar los datos. Como no hay borrado automático, decida el procedimiento de borrado y quién se encarga.
- **Derechos de acceso**: a quién se concede `viewer` o superior. Gestione el acceso partiendo de que las lecturas no se registran.
- **Medidas de seguridad**: permisos y cifrado del archivo de la base de datos y de sus copias de seguridad. Las claves de API introducidas en la interfaz se guardan en la base de datos en texto plano.
- **Solicitudes de los interesados**: procedimientos y plazos ante solicitudes de acceso, rectificación, supresión, cese del uso, etc.
- **En caso de fuga**: saber, a partir de esta página, qué tablas y qué destinos externos contienen datos.
- **Monitorización de empleados**: normas internas y aviso cuando el sensor de host o Gate registran comunicaciones o actividad de los empleados.
- **Engaño**: la redacción y la ubicación de los señuelos y los canarios de IA ([Engaño (Mirage)](Deception-es)).

## Páginas relacionadas

- [Configuración de LLM y costos](LLM-es): configuración del proveedor y del enmascaramiento
- [Conexión de sensores](Sensors-es): configuración de Gate y Agent
- [Referencia de configuración](Configuration-es)
- [Guía de la interfaz web](Web-UI-es): roles y pantallas
