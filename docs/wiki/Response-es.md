> 🌐 [日本語](Response) · [English](Response-en) · [中文](Response-zh) · **Español**

# Respuesta (flujo de aprobación)

Cuando TOKIWA detecta una amenaza, **propone** acciones de respuesta, pero **no ejecuta nada hasta que una persona lo aprueba**.
Todos los bloqueos tienen caducidad (TTL) y pueden revertirse.

## Ciclo de vida

```
proposed (propuesta) ──aprobar──▶ approved ──ejecución correcta──▶ active (activa) ──vencimiento──▶ expired
    │                                │                                 └──revertir──▶ reverted
    └──rechazar──▶ rejected          └──ejecución fallida──▶ failed
```

| Operación | Quién | Observaciones |
|---|---|---|
| Proponer | LLM (triaje) / reglas / usuario | Si ya existe una propuesta del mismo tipo y para el mismo objetivo, no se crea otra: se añade el motivo a la existente |
| Aprobar / rechazar | `analyst` o superior | Al aprobarla, se ejecuta de inmediato |
| Revertir | `analyst` o superior | Acciones en estado `active` que admiten reversión |
| Vencimiento | Automático (comprobación cada 30 segundos) | Se levanta al superar el TTL |

Todas las operaciones quedan registradas en el log de auditoría.

## Tipos de acción de respuesta

| Tipo | Objetivo | Qué ocurre |
|---|---|---|
| `block_ip` | IP / CIDR | Gate devuelve 403 a ese origen |
| `rate_limit` | IP / CIDR | Gate limita el número de solicitudes por minuto (60 por defecto). Si se supera, devuelve 429 |
| `tarpit` | IP / CIDR | Gate retrasa las respuestas (2000 ms por defecto, máximo 30 segundos) |
| `deceive` | IP / CIDR | Gate sustituye por señuelos todas las respuestas a ese origen |
| `nftables_block` | Una sola IP | La añade a un set de nftables del host (**deshabilitado por defecto**) |
| `deploy_canary` | Ruta | Despliega activos de engaño (señuelos, honeytokens, canarios de IA) |
| `notify` | — | Envía a los canales de notificación |
| `webhook` | — | Envía un JSON de formato fijo a un webhook configurado |

Las acciones de respuesta que afectan a Gate se aplican la próxima vez que Gate obtiene la política (en un máximo de 5 segundos por defecto).

## Salvaguardas

1. **Nada se ejecuta sin aprobación**. El proceso de ejecución solo acepta filas aprobadas (con aprobador y hora de aprobación).
   Esto se garantiza mediante pruebas (todas las combinaciones de tipo × origen de la propuesta, aprobaciones simultáneas, inspección estática del código).
2. **El texto libre del LLM no llega al sistema de ejecución**. El ejecutor solo recibe el tipo validado, IP / CIDR normalizados, parámetros tipados y el TTL.
   No se generan cadenas de comandos de shell.
3. La validación de propuestas rechaza objetivos como los siguientes:
   - Valores que no pueden interpretarse como IP / CIDR (nombres de host, valores que contienen `;`, etc.)
   - Rangos demasiado amplios (más amplios que /16 en IPv4 o que /48 en IPv6; por ejemplo, `0.0.0.0/0`)
   - Los que se solapan con los **objetivos protegidos** (`response.protected_cidrs`; por defecto `127.0.0.0/8`, `::1/128`)
   - Las direcciones IP del propio servidor (`response.protect_server_addresses`, activado por defecto)
4. Justo antes de la ejecución se **vuelve a validar** con la configuración vigente (por ejemplo, si se añade un objetivo protegido después de la propuesta, la acción pasa a `failed`).

> 💡 Se recomienda encarecidamente añadir a `response.protected_cidrs` las IP de los equipos de administración, de los sistemas de monitorización y de los balanceadores de carga ascendentes.

## TTL (periodo de validez)

- 60 minutos por defecto (`response.default_ttl_minutes`), máximo 7 días (`response.max_ttl_minutes`). Los valores que superan el máximo se recortan.
- Al vencer, se levanta automáticamente.

## Aprobación automática (desactivada por defecto)

Se puede omitir la aprobación solo para determinados tipos. Funciona únicamente cuando se habilitan **los dos ajustes**.

```yaml
response:
  auto_approve_enabled: true
  auto_approve_actions: ["rate_limit", "tarpit"]   # Solo los tipos enumerados aquí
```

En las acciones de respuesta aprobadas automáticamente, el aprobador se registra como `policy`. La aprobación automática de bloqueos (`block_ip`) debe decidirse con cautela, porque un falso positivo tiene un impacto grande.

> La "aprobación por dos personas", en la que el proponente y el aprobador deben ser personas distintas, todavía no se exige en v0.1 (está previsto añadirla como opción de configuración en la próxima fase de desarrollo).

## Bloqueo con nftables (opcional)

Sirve para detener también el tráfico que no pasa por Gate. **Está deshabilitado por defecto** y, mientras no se habilite, falla siempre.
TOKIWA no crea tablas, sets ni reglas; solo añade y elimina elementos de los sets, por lo que el administrador debe prepararlos de antemano.

```bash
nft add table inet tokiwa
nft add set inet tokiwa blocklist  '{ type ipv4_addr; flags timeout; }'
nft add set inet tokiwa blocklist6 '{ type ipv6_addr; flags timeout; }'
nft add chain inet tokiwa input '{ type filter hook input priority 0; policy accept; }'
nft add rule inet tokiwa input ip  saddr @blocklist  drop
nft add rule inet tokiwa input ip6 saddr @blocklist6 drop
```

Después, defina `TOKIWA_RESPONSE__NFTABLES_ENABLED=true`. Compruebe en su distribución la sintaxis anterior y los permisos necesarios
para ejecutarlo sin ser root (`CAP_NET_ADMIN`, etc.) (aún no verificado).

## Notificaciones

Si registra Webhook / Slack / Discord / correo electrónico en **Settings → Notifications** (Configuración → Notificaciones), se envían notificaciones en los siguientes casos.

| Desencadenante | Condición |
|---|---|
| Creación de alerta | Severidad igual o superior al mínimo del canal |
| Creación de incidente | Ídem |
| Actualización de incidente | Solo cuando aumenta la severidad |
| Propuesta de acción de respuesta | Se envía como solicitud de aprobación (puede desactivarse con `notify.notify_action_proposals`) |

- Un mismo contenido se envía como máximo una vez cada 10 minutos (`notify.dedup_minutes`). No obstante, se envía si la severidad aumenta.
- El idioma de las notificaciones se define con `notify.language` (`ja` / `en` / `both`). Los enlaces usan `notify.public_ui_url`.
- **Protección contra SSRF**: solo se admiten destinos http / https y no se siguen redirecciones. Por defecto, se rechaza el destino si la resolución de nombres
  da una dirección privada (loopback, red interna, metadatos de la nube, etc.). También se pueden limitar los hosts permitidos
  con `notify.allowed_hosts`.
- Se recomienda no guardar la contraseña del correo en la base de datos y pasarla mediante `password_env` (nombre de una variable de entorno).
