> 🌐 [日本語](Threat-Intel) · [English](Threat-Intel-en) · [中文](Threat-Intel-zh) · **Español**

# Inteligencia de vulnerabilidades

Esta función ingiere periódicamente información de vulnerabilidades, la coteja con los activos registrados y emite recomendaciones priorizadas (avisos).
Además, mediante la búsqueda web del LLM, investiga periódicamente informes de 0day y de explotación.

## Fuentes que se ingieren

| Fuente | Contenido |
|---|---|
| CISA KEV | Catálogo de vulnerabilidades cuya explotación real se ha confirmado |
| EPSS | Estimación de la probabilidad de explotación en los próximos 30 días |
| NVD | Detalles de los CVE, CVSS, productos afectados (CPE) |
| OSV | Vulnerabilidades de paquetes de código abierto (PyPI, npm, Go, Maven, etc.) |
| JVN | Información de vulnerabilidades de Japón |
| GitHub Security Advisories (GHSA) | Avisos de GitHub |
| RSS | JPCERT/CC, IPA, CISA, The Hacker News, BleepingComputer (por defecto) |

- Por defecto se sincroniza cada 360 minutos (6 horas) (`intel.sync_interval_minutes`).
- La sincronización requiere **conexiones salientes** a estos servicios.
- Sin clave de API, NVD impone límites más estrictos a la velocidad de obtención. GitHub también es más estable con un token.

```bash
export TOKIWA_INTEL__NVD_API_KEY=...       # Opcional
export TOKIWA_INTEL__GITHUB_TOKEN=...      # Opcional
```

> ⚠️ Para JVN se ha anunciado una renovación de MyJVN a partir de abril de 2026. Es posible que la obtención basada en los feeds antiguos haya dejado de funcionar,
> y el funcionamiento con datos reales aún no está verificado.

## Uso

1. **Registrar los activos**: en la página **Assets** (Activos), registre los hosts, servicios, aplicaciones web y aplicaciones LLM que se deben proteger, y el software que se ejecuta en ellos
   (proveedor, nombre del producto, versión, CPE, ecosistema de OSV).
2. **Esperar a la sincronización (o ejecutarla manualmente)**: la sincronización puede iniciarse desde **Intelligence → Sources** (Inteligencia → Fuentes). También puede ejecutarse desde la CLI.

   ```bash
   cd backend
   uv run tokiwa intel sync              # Todas las fuentes habilitadas
   uv run tokiwa intel sync -s kev       # Solo una fuente concreta
   uv run tokiwa intel status            # Estado de sincronización por fuente
   uv run tokiwa intel show CVE-2021-44228
   ```

3. **Ver los resultados**: consúltelos en las pestañas de la página **Intelligence**.

| Pestaña | Contenido |
|---|---|
| **Vulnerabilities** (Vulnerabilidades) | Integración de todas las fuentes por CVE (si figura en KEV, EPSS, CVSS) |
| **Asset matches** (Coincidencias con activos) | Vulnerabilidades que coinciden con el software de los activos. Permite gestionar su estado (sin atender / atendida, etc.) |
| **Advisories** (Avisos) | Recomendaciones priorizadas por el LLM. Se generan dando prioridad a lo que figura en KEV, tiene un EPSS alto o coincide con activos |
| **News** (Noticias) | Artículos de RSS |
| **Web research** (Investigación web) | Resultados de la investigación de 0day e informes de explotación realizada por el LLM. También puede ejecutarse manualmente indicando un tema |
| **Sources** (Fuentes) | Última sincronización y número de elementos de cada fuente |

## Avisos y propuesta de reglas de detección

Además del resumen del impacto, la prioridad y la respuesta recomendada, los avisos pueden incluir un **borrador de regla de detección en formato Sigma**.
Los borradores se validan y se guardan como "propuestas" en **Rules → LLM proposals** (Reglas de detección → Propuestas del LLM), y **no se activan automáticamente**.
Una persona los revisa y los adopta.

## Vinculación con los incidentes

Si una alerta hace referencia a un CVE y ese CVE figura en KEV, se eleva la prioridad del incidente.
La tarjeta **KEV matches** (Coincidencias KEV) del **Dashboard** (Panel) indica el número de coincidencias entre vulnerabilidades con explotación conocida y activos.

## Investigación web (investigación periódica de 0day)

- Por defecto, cada 12 horas (`intel.research_interval_hours`) investiga los temas de `intel.research_topics`.
- Como utiliza la **búsqueda web del lado del servidor** de Claude, **solo realiza búsquedas reales cuando hay configurada una clave de API de Anthropic**.
  Con el LLM simulado (mock) no se realizan búsquedas, y así se indica en el resultado.
- Usa el modelo profundo, por lo que genera costos de LLM. Si no lo necesita, puede detenerlo con `intel.research_enabled: false`.
- Los resúmenes de los resultados son salida del LLM. Antes de tomar decisiones importantes, verifique siempre las fuentes originales.

## Ajustes principales (`intel.*`)

| Clave | Por defecto | Descripción |
|---|---|---|
| `enabled` | true | Toda la función de inteligencia |
| `sync_interval_minutes` | 360 | Intervalo de sincronización |
| `sources` | Todas true | Activación / desactivación por fuente (`kev`, `epss`, `nvd`, `osv`, `jvn`, `ghsa`, `rss`) |
| `rss_feeds` | 5 | URL de los feeds RSS que se ingieren |
| `research_enabled` / `research_interval_hours` | true / 12 | Investigación web |
| `research_topics` | 2 temas: 0day y ataques impulsados por IA | Temas de investigación |
| `epss_alert_threshold` | 0.1 | Umbral a partir del cual se considera un aumento brusco de EPSS |
| `nvd_lookback_days` | 3 | Número de días hacia atrás que se obtienen de NVD |
