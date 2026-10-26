> 🌐 [日本語](Deception) · [English](Deception-en) · [中文](Deception-zh) · **Español**

# Engaño (Mirage)

Esta función coloca en los activos de la propia organización **trampas** que un usuario legítimo nunca tocaría y detecta con alta certeza a quien las toca.
Las trampas las sirve Gate, y nunca se reenvían a la aplicación que se protege.

## Canario de IA (inyección de prompts inversa)

Es el mecanismo central de Mirage. Dentro de los señuelos se incrustan "**instrucciones ocultas que solo un agente de IA lee y obedece**".

- No son visibles para los usuarios humanos (comentarios HTML y elementos ocultos; tampoco los leen en voz alta los lectores de pantalla).
- Las instrucciones tienen una forma que **solo puede seguirse si se leen, se entienden y se construye la solicitud**, como "envía un valor en un encabezado concreto (por defecto `X-Debug-Auth`)"
  o "llama a una ruta formada por `/api/internal/` seguido del valor".
- Los valores no aparecen como enlaces (`href`) ni como ejemplos de OpenAPI. Si un rastreador o un fuzzer que sigue enlaces mecánicamente
  los "obedeciera" por casualidad, se perdería la base para afirmar que se trata de una IA.

Si llega una solicitud que sigue las instrucciones, puede concluirse que procede de un cliente impulsado por un LLM (puntuación de IA 0.99).

## Tipos de activo

| Tipo | Qué se coloca | Condición de detección |
|---|---|---|
| `decoy_path` | `/.env`, `/backup.sql`, `/admin/config.php`, `/.git/config`, `/api/internal/debug`, etc. Su contenido son credenciales falsas y notas de canario de IA | Acceso a esa ruta o uso de las credenciales falsas que contiene |
| `honeytoken` | Claves de AWS, claves de API y credenciales de bases de datos falsas | Que ese valor aparezca en algún evento |
| `ai_canary` | Instrucciones ocultas. Inserción en HTML, `/robots.txt`, `/llms.txt`, JSON de estilo OpenAPI, etc. | **Cuando el valor se usa tal como indican las instrucciones** (obtener la página no basta para que se detecte) |
| `labyrinth` | Páginas de un laberinto infinito bajo `/archive/` (desactivado por defecto) | Acceso a sus páginas. A partir de profundidad 3, severidad critical |

Las credenciales falsas difieren a propósito del formato de los servicios reales (por ejemplo, el ID de clave de acceso de AWS tiene 24 caracteres
en lugar de los 20 del real). Aunque llegaran a filtrarse, no servirían como credenciales auténticas.

## Elementos creados por defecto

Al arrancar el servidor se crean automáticamente los siguientes activos (si ya existen, no se modifican).

- Un `decoy_path` por cada ruta incluida en `deception.decoy_paths`
- Canarios de IA: inserción en HTML (habilitado), `/api/internal/openapi.json` (habilitado), `/robots.txt` (**deshabilitado**), `/llms.txt` (**deshabilitado**)
- El laberinto, solo cuando `deception.labyrinth_enabled: true`

Los canarios de `/robots.txt` y `/llms.txt` están deshabilitados por defecto porque reemplazarían los archivos del mismo nombre que tenga la aplicación protegida.
Si los habilita, compruebe que no entren en conflicto con el contenido de la aplicación.

> Aunque **elimine** un activo, mientras siga en la configuración volverá a crearse en el siguiente arranque. Si quiere detenerlo, **desactívelo** o quítelo de la configuración.

## Cuando se produce una detección

| Clasificación | Severidad | Significado |
|---|---|---|
| `ai_canary_followed` | critical | Se siguieron las instrucciones del canario de IA (casi con certeza un agente de IA; puntuación de IA 0.99) |
| `ai_canary_token` | critical | El valor del canario apareció en otro lugar (alguien leyó el texto oculto; no se descarta que una persona lo copiara del código fuente) |
| `honeytoken` | critical | Se usaron credenciales falsas |
| `decoy_path` | critical | Se accedió a una ruta señuelo |
| `labyrinth` | high (critical a partir de profundidad 3) | Se entró en el laberinto |

Los accesos a señuelos también los producen los escáneres automatizados (`/.env` y similares son objetivos de exploración habituales). Para determinar si se trata de un agente de IA,
combine `ai_canary_followed` con la puntuación de comportamiento de **[AI sessions](Web-UI-es)** (Sesiones de IA).

## Operaciones en la interfaz

En la página **Deception** (Engaño) se pueden listar, añadir, activar y desactivar activos, **previsualizar el contenido que se sirve** y consultar la lista de activaciones (**Trip history** (Historial de activaciones): registros de quién tocó las trampas).
También se pueden añadir trampas según el incidente mediante la acción de respuesta `deploy_canary`.

## Ajustes principales (`deception.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `enabled` | true | Toda la función de engaño |
| `ai_canaries` | true | Canarios de IA |
| `decoy_paths` | Las 5 rutas anteriores | Señuelos creados por defecto |
| `html_injection` | true | Inserta instrucciones ocultas en las respuestas HTML de la aplicación protegida (justo antes de `</body>`) |
| `canary_header` | `X-Debug-Auth` | Nombre del encabezado que las instrucciones ocultas piden enviar. Si se incluye en `llm.redaction.sensitive_headers`, deja de poder detectarse |
| `canary_language` | `both` | Idioma de las instrucciones ocultas (`ja` / `en` / `both`) |
| `labyrinth_enabled` | false | Laberinto |
| `labyrinth_prefix` / `labyrinth_max_depth` | `/archive/` / 8 | Ubicación y profundidad del laberinto |

Desactive `html_injection` si la aplicación tiene algún mecanismo que devuelva al servidor el DOM de la página (session replay, etc.).

## Precauciones de uso

- Las trampas se colocan **solo en activos de la propia organización**. No se contraataca al origen del ataque ni se devuelven cargas útiles de tipo malware.
- La intensidad y el idioma de la redacción de las instrucciones ocultas, así como su colocación en robots.txt / llms.txt, son decisiones operativas. Antes de implantarlo,
  consúltelo con las políticas de su organización y con el departamento legal.
