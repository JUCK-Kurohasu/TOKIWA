> 🌐 [日本語](Web-UI) · [English](Web-UI-en) · [中文](Web-UI-zh) · **Español**

# Guía de la interfaz web

La interfaz de TOKIWA se abre en `http://<servidor>:8788`. La barra lateral izquierda se divide en 5 grupos.
Con los botones de la esquina superior derecha se puede cambiar el **idioma de visualización (japonés / English)** y el **tema claro / oscuro**.
Las alertas y los incidentes se actualizan en tiempo real (SSE).

Las fechas y horas siempre llevan el nombre de la zona horaria (por ejemplo `11/11/2026, 09:43:09 GMT+9`). El botón del reloj de la esquina superior derecha
(muestra `JST`, `UTC`…) cambia la **zona horaria de visualización (local del navegador / UTC)**; la elección se recuerda en cada navegador. Al pasar el ratón
sobre una hora también se muestra el valor ISO 8601 en UTC (por ejemplo `2026-11-11T00:43:09.000Z`). La API, la vista de datos sin procesar (JSON), el Gate y los registros usan siempre UTC.
El periodo personalizado de la pantalla Events (eventos) también se interpreta en la zona horaria de visualización.

> La interfaz web solo está disponible en japonés e inglés. En esta wiki, las etiquetas de la interfaz se citan en inglés y en negrita,
> con su traducción al español entre paréntesis la primera vez que aparecen en cada página.

## Roles (permisos)

| Rol | Qué puede hacer |
|---|---|
| `viewer` | Solo lectura. El cuerpo de las peticiones, las query strings, los valores de cabeceras, las líneas de comandos y los prompts de los eventos se muestran enmascarados (`[redacted: analyst role required]`). Por defecto no puede usar el copiloto (`copilot.min_role`) |
| `analyst` | Además de la lectura: ejecutar triajes, actualizar incidentes, **aprobar, rechazar y revertir acciones de respuesta**, editar los activos de engaño, etc. |
| `admin` | Todo. Gestión de usuarios, tokens de API, canales de notificación y configuración del LLM |

El usuario creado inicialmente en la página **/setup** (configuración inicial) es `admin`. Los usuarios se añaden en **Settings → Users** (Configuración → Usuarios).

Un inicio de sesión dura 12 horas por defecto (`server.token_ttl_minutes`). **Log out** (cerrar sesión, arriba a la derecha) cierra las sesiones de ese usuario en **todos los dispositivos**. Cambiar la contraseña o el rol de un usuario también cierra sus sesiones, por lo que debe volver a iniciar sesión. Los administradores pueden cerrar las sesiones de otro usuario en todos los dispositivos con **Revoke sessions** (revocar sesiones) en **Settings → Users** (por ejemplo, si se sospecha que se robaron sus credenciales).

## Monitor (Monitorización)

### Dashboard (Panel)

Ofrece una visión global de las últimas 24 horas. Las señales procedentes de agentes de IA se muestran en **morado**.

- Tarjetas superiores: **Alerts (24h)** (número de alertas, por severidad), **Open incidents** (incidentes abiertos), **AI agent sessions (24h)** (número de sesiones de agentes de IA),
  **LLM cost (today)** (costo del LLM de hoy y presupuesto), **Pending actions** (**acciones de respuesta pendientes de aprobación**) y **KEV matches** (número de coincidencias entre vulnerabilidades con explotación conocida (KEV) y activos)
- Actividad: evolución de eventos y alertas (de 6 horas a 7 días)
- Feed en directo: nuevas alertas, incidentes y propuestas de acción de respuesta llegados desde que se abrió la página
- Principales orígenes, principales reglas, incidentes recientes

### Alerts (Alertas)

Lista de los resultados de detección individuales. Puede filtrarse por estado, severidad, categoría, IP de origen y puntuación de IA.
En la vista de detalle se pueden consultar los eventos en que se basa (evidencias) y el resultado del triaje del LLM, y volver a ejecutar el triaje manualmente.

### AI sessions (Sesiones de IA)

Unidades de comportamiento (sesiones) agrupadas por **origen + huella del cliente**. A partir de las características del comportamiento
se estima si se trata de "agente de IA / escáner automatizado / humano / legítimo" y se asigna una puntuación de IA.

- Lista: puntuación de IA, clasificación, número de solicitudes, tasa de errores, número de rutas, duración
- Detalle: cronología de las solicitudes. El intervalo desde la solicitud anterior (ms) se colorea en bandas "ráfaga / intermedio / espera de razonamiento / largo",
  lo que permite ver el ritmo **ráfaga → pausa → ráfaga** característico de los agentes de IA. También se muestra el desglose de la puntuación (qué características influyeron).

### Hosts (Equipos)

Información de los hosts enviada por TOKIWA Agent. Pestañas: **Ports** (Puertos; lista de puertos en escucha) y **Baselines** (Líneas base; lista de permitidos).
Los puertos en escucha que no figuran en la línea base se detectan como "desviación".

## Investigate (Investigación)

### Copilot (Copiloto)

Chat que permite hacer preguntas en lenguaje natural sobre los datos de TOKIWA (por ejemplo: "¿Qué orígenes se han clasificado hoy como agentes de IA?").
Las herramientas que puede usar el copiloto son **de solo lectura**: no puede cambiar la configuración ni ejecutar acciones de respuesta. Si no se ha configurado un LLM,
las respuestas son simuladas (mock).

Como el LLM podría seguir instrucciones que un atacante haya colocado en la telemetría, los enlaces de las respuestas se tratan así:

- Los enlaces internos de TOKIWA solo se abren en la misma pestaña si apuntan a pantallas conocidas (alertas, incidentes, sesiones, eventos…).
- Los enlaces externos solo se pueden pulsar si son páginas https de sitios permitidos (NVD, MITRE, CISA, JVN, OSV, FIRST), y junto a la etiqueta se muestra el nombre de host real.
  El resto se muestra como texto no pulsable, junto con su nombre de host y "link disabled" (enlace desactivado).
- Si una etiqueta tiene forma de URL pero no coincide con el destino real, se muestra la advertencia "label and destination differ" (la etiqueta y el destino no coinciden).

Los sitios permitidos se configuran en `EXTERNAL_LINK_ALLOWLIST` de `frontend/src/components/common/linkPolicy.ts` (requiere volver a compilar).

### Incidents (Incidentes)

Agrupaciones de alertas relacionadas por origen, sesión y entidad.

- Lista: severidad, estado, **Actor attribution** (Atribución del actor: agente de IA / humano / escáner, etc.), puntuación de IA
  (la atribución la deciden las reglas y el comportamiento. Solo cuando las reglas no pueden atribuir se usa el veredicto del LLM, y
  solo para elevarla a agente de IA / escáner; un veredicto del LLM de «humano» o «benigno» no la cambia)
- Detalle: fase del ataque (kill chain: reconocimiento → acceso inicial → …), triaje del LLM (resumen, fundamentación, acción de respuesta recomendada),
  "evidencias de participación de IA" señaladas por el LLM y alertas relacionadas. Permite asignar el **Assignee** (Responsable) y actualizar el **Status** (Estado).

El servidor verifica que las evidencias citadas en el triaje del LLM (ID de evidencia) correspondan a eventos que existen realmente.

### Events (Eventos)

Búsqueda de los eventos sin procesar ingeridos. Puede filtrarse por tipo, dataset, IP de origen, host, periodo y palabra clave (ruta / User-Agent).

Si una ruta, un User-Agent, una cabecera o un cuerpo contiene **caracteres invisibles o que alteran el orden de visualización**
(el control bidireccional U+202E, el de ancho cero U+200B…), cada uno se muestra como `⟨U+202E⟩` en color de advertencia y la fila o el evento
recibe la insignia "Contains invisible / bidi control characters" (contiene caracteres invisibles o de control bidireccional). Así se evitan trucos
como mostrar `invoice⟨U+202E⟩fdp.exe` como `invoiceexe.pdf`. La vista de datos sin procesar (JSON) los muestra como `\u202E`.
Solo cambia la visualización; las búsquedas y los filtros usan la cadena original. Se aplica a la lista de eventos, el detalle de eventos,
la evidencia de alertas, el detalle de sesiones y las respuestas y resultados de herramientas del copiloto.

## Intelligence (Inteligencia)

### Intelligence

Información de vulnerabilidades y resultados de su cotejo con los activos. Pestañas: **Vulnerabilities** (Vulnerabilidades; integración de KEV / EPSS / NVD / JVN / OSV / GHSA),
**Asset matches** (Coincidencias con activos), **Advisories** (Avisos; recomendaciones priorizadas por el LLM), **News** (Noticias; RSS), **Web research**
(Investigación web; investigación de 0day con el LLM) y **Sources** (Fuentes; estado de las fuentes). Más detalles en [Inteligencia de vulnerabilidades](Threat-Intel-es).

### Assets (Activos)

Aquí se registran los hosts que se deben proteger y el software que se ejecuta en ellos (nombre del producto, versión, CPE). Los activos registrados se usan para el cotejo
con la información de vulnerabilidades y para priorizar los incidentes (si corresponden a una entrada de KEV).

### Rules (Reglas de detección)

- **Detectors** (Detectores): activación / desactivación de los detectores integrados (firmas de ataques web, comportamiento de IA, engaño, puertos, etc.)
- **Sigma rules** (Reglas Sigma): gestión de reglas en formato Sigma (25 incluidas + las añadidas). Cuando una de las 14 reglas
  web incluidas coincide con una petición en la que también alerta el detector web integrado del mismo tipo, ambas se fusionan
  (una sola alerta, registrada en `details.corroborated_by`); si el detector está activado pero no alerta, la alerta de la regla
  se registra como low. La regla conserva su propia severidad solo mientras ese detector está desactivado
- **LLM proposals** (Propuestas del LLM): reglas propuestas por el LLM a partir de la información de vulnerabilidades. **No se activan automáticamente**: se revisan y se adoptan

## Respond (Responder)

### Response (Respuesta)

Lista de las acciones de respuesta propuestas por el LLM, las reglas y los usuarios. Pestañas: **Awaiting approval** (Pendientes de aprobación) / **Active** (Activas) / **History** (Historial) / **Suppressions** (Supresiones: objetivos marcados como "no volver a proponer" al rechazar o revertir; aquí se levantan).
Aprobar, rechazar y revertir requiere el rol `analyst` o superior. Más detalles en [Respuesta (flujo de aprobación)](Response-es).

### Deception (Engaño)

Gestión de señuelos, honeytokens, canarios de IA y laberintos, y registro de las veces que alguien los ha tocado (activaciones, en inglés *trips*).
También se puede previsualizar el contenido que se sirve. Más detalles en [Engaño (Mirage)](Deception-es).

## System (Sistema)

### LLM

- **Settings** (Configuración): proveedor, modelos (rápido / profundo; desplegable para Anthropic), presupuesto diario, idioma de salida, clave de API (solo escritura). Incluye el botón **Connection test** (Prueba de conexión)
- **Usage** (Uso): costo diario, número de llamadas y número de tokens (por finalidad)
- **Call log** (Registro de llamadas): log de auditoría de todas las llamadas al LLM. Los administradores también pueden ver el texto enmascarado de las entradas y las respuestas

Más detalles en [Configuración de LLM y costos](LLM-es).

### Settings (Configuración; solo administradores)

**Users** (Usuarios), **API tokens** (Tokens de API; para sensores, se muestran una sola vez al crearlos), **Notifications** (Notificaciones; Webhook / Slack / Discord / correo electrónico),
**System** (Sistema; versión, entorno, base de datos y estado del proveedor de LLM, detectores, lista de trabajos en segundo plano y ejecución manual).
