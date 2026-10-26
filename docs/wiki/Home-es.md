> 🌐 [日本語](Home) · [English](Home-en) · [中文](Home-zh) · **Español**

# TOKIWA Wiki

**TOKIWA (常磐)** es un **SIEM / XDR impulsado por LLM** que detecta y defiende frente a ciberataques realizados con IA generativa (agentes LLM).
Se ha creado como el producto del lado defensivo (Blue) que forma pareja con **ARTEX**, un sistema autónomo de pruebas de penetración basado en IA.

> ⚠️ **En desarrollo (v0.1.0)**. Está pensado para usarse en laboratorios o en entornos que usted administra y para los que tiene autorización de pruebas.

## Qué hace TOKIWA

Además de los "ataques que coinciden con firmas", el punto fuerte de los SIEM tradicionales, se centra en distinguir **comportamientos propios de un agente de IA**.

| Aspecto | Ejemplo |
|---|---|
| Ritmo de espera de razonamiento | Se alternan ráfagas de llamadas a herramientas en paralelo con "pausas" de espera de la inferencia |
| Adaptación tras errores | Justo después de recibir un 500 o un 403, reintenta modificando la carga útil poco a poco |
| Exploración semántica | Descubre en bundles de JS o en OpenAPI API que no están enlazadas y las llama |
| Obediencia a instrucciones ocultas | Sigue las "instrucciones que solo una IA lee y obedece" incrustadas en señuelos (canario de IA) |

El LLM realiza el triaje de las alertas detectadas, con su fundamentación, y **propone** acciones de respuesta (bloqueo, limitación de tasa, etc.).
**Solo se ejecutan cuando una persona las aprueba**.

## Funcionamiento (resumen)

```
 Atacante / usuario ──▶ TOKIWA Gate (proxy inverso) ──▶ Aplicación web protegida
                          │  Captura HTTP incluido el cuerpo y aplica al instante bloqueo, limitación de tasa y señuelos
                          ▼
                   TOKIWA Server (API + Web UI)
                     Ingesta → detección (firmas, Sigma, comportamiento de IA) → correlación (creación de incidentes)
                     → triaje con LLM → propuesta de acción de respuesta → aprobación humana → aplicación en Gate
                     + inteligencia de vulnerabilidades (KEV / EPSS / NVD / OSV / JVN / GHSA / RSS)
                     + engaño (señuelos, honeytokens, canarios de IA)
                     + copiloto SOC (diálogo con herramientas de solo lectura)
                          ▲
 TOKIWA Agent (host) ── puertos, conexiones, logs de nginx / Caddy / Suricata / Zeek
```

## Por dónde empezar

| Qué quiere hacer | Página |
|---|---|
| Ponerlo en marcha cuanto antes (10 minutos) | [Inicio rápido](Quick-Start-es) |
| Usarlo de forma habitual con Docker o desplegarlo en un entorno cercano a producción | [Instalación y operación](Installation-es) |
| Supervisar sus propias aplicaciones web o servidores | [Conexión de sensores](Sensors-es) |
| Saber cómo leer las pantallas | [Guía de la interfaz web](Web-UI-es) |
| Configurar el LLM (clave de API, costos, modelos) | [Configuración de LLM y costos](LLM-es) |
| Aprobar y gestionar acciones de respuesta como los bloqueos | [Respuesta (flujo de aprobación)](Response-es) |
| Usar señuelos y canarios de IA | [Engaño (Mirage)](Deception-es) |
| Cotejar información de 0day y vulnerabilidades con sus activos | [Inteligencia de vulnerabilidades](Threat-Intel-es) |
| Hacer pruebas con el simulador de ataques o con ARTEX | [Laboratorio y evaluación](Lab-and-Evaluation-es) |
| Consultar opciones de configuración y comandos | [Referencia de configuración](Configuration-es) / [Referencia de la CLI](CLI-es) |
| Algo no funciona | [Solución de problemas](Troubleshooting-es) |

## Política de seguridad

TOKIWA es una herramienta de defensa. Los siguientes compromisos se cumplen mediante el diseño y las pruebas.

1. **Los logs que se pasan al LLM se tratan siempre como "datos no confiables"**. Para que el LLM no siga instrucciones que un atacante haya insertado en los logs (inyección de prompts), se aíslan y se enmascaran antes de pasárselos.
2. **La salida del LLM no se conecta directamente al sistema de ejecución**. Lo único que el LLM puede producir son "tipos de acción de respuesta incluidos en la lista de permitidos" e "IP / CIDR / TTL validados"; no se le permite generar cadenas de comandos ni de configuración.
3. **Por defecto, las acciones de respuesta requieren aprobación humana**. La aprobación automática se limita a los tipos para los que se han habilitado explícitamente dos ajustes. Todos los bloqueos tienen caducidad (TTL) y pueden revertirse.
4. **La defensa activa se realiza solo sobre activos de la propia organización** (señuelos, laberintos, tarpit, etc.). No se contraataca al origen del ataque (hack-back).

## Estado de verificación actual (v0.1.0)

| Elemento | Estado |
|---|---|
| Pruebas automatizadas del backend (unas 1280), compilación del frontend, compilación de la imagen Docker y pruebas de humo | ✅ Se ejecutan continuamente en CI |
| Flujo completo en local (simulador de ataques → Gate → detección → incidente → aprobación → Gate devuelve 403 → reversión) | ✅ Comprobado (LLM simulado) |
| Calidad y costo del triaje con un LLM real (Claude) | ⏳ Aún no evaluado |
| Arranque del laboratorio Docker con `lab/compose.yaml` | ⏳ Aún no verificado |
| Obtención de datos reales de los feeds de vulnerabilidades | ⏳ Aún no verificado (validado con datos de prueba basados en las especificaciones) |
| Ejercicio de purple team contra un ARTEX real | ⏳ Aún no realizado |

Las cifras de exactitud de la detección (precisión y exhaustividad de la clasificación de IA, etc.) se obtuvieron con datos sintéticos y podrían ser más bajas en entornos reales.

## Licencia y enlaces

- Licencia: Apache License 2.0 (provisional)
- Repositorio: [JUCK-Kurohasu/TOKIWA](https://github.com/JUCK-Kurohasu/TOKIWA)
- Documentación para desarrolladores: `docs/` del repositorio (arquitectura, contrato de API, decisiones de diseño), `AGENTS.md`, `HANDOFF.md`
