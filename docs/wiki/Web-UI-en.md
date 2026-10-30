> 🌐 [日本語](Web-UI) · **English** · [中文](Web-UI-zh) · [Español](Web-UI-es)

# Web UI guide

Open the TOKIWA UI at `http://<server>:8788`. The sidebar on the left is divided into five groups.
Use the buttons at the top right to switch the **display language (Japanese / English)** and the **light / dark theme**.
Alerts and incidents update in real time (SSE).

## Roles (permissions)

| Role | What it can do |
|---|---|
| `viewer` | View only |
| `analyst` | Everything a viewer can do, plus running triage, updating incidents, **approving, rejecting, and reverting response actions**, editing deception assets, and more |
| `admin` | Everything. Manages users, API tokens, notification channels, and LLM settings |

The user you create first on the setup page is an `admin`. Add users under **Settings → Users**.

## Monitor

### Dashboard

An overview of the past 24 hours. Signals that come from AI agents are shown in **purple**.

- Top cards: alert count (by severity), open incidents, number of AI agent sessions, today's LLM cost and budget,
  **response actions awaiting approval**, and the number of matches between known exploited vulnerabilities (KEV) and your assets
- Activity: event and alert trends (6 hours to 7 days)
- Live feed: new alerts, incidents, and response action proposals that arrived after you opened the page
- Top sources, top rules, recent incidents

### Alerts

A list of individual detections. You can filter by status, severity, category, source IP, and AI score.
The detail view shows the events the detection was based on (evidence) and the LLM triage result, and you can re-run triage manually.

### AI sessions

Units of behavior (sessions) grouped by **source + client fingerprint**. From behavioral features, TOKIWA estimates
"AI agent / automated scanner / human / benign" and assigns an AI score.

- List: AI score, classification, request count, error rate, path count, duration
- Detail: a timeline of requests. The interval since the previous request (ms) is color-coded into bands, "burst / intermediate / thinking pause / long",
  so you can see the **burst → pause → burst** rhythm typical of AI agents. The score breakdown (which features contributed) is also shown.

### Hosts

Host information sent by TOKIWA Agent. Tabs: **Ports** (list of listeners) and **Baselines** (allowlist).
Listeners that are not in the baseline are detected as "deviations".

## Investigate

### Copilot

A chat where you can ask questions about TOKIWA's data in natural language (for example, "Which sources were classified as AI agents today?").
The tools the Copilot can use are **read-only**; it cannot change settings or execute response actions. If no LLM is configured,
it gives mock responses.

### Incidents

Related alerts grouped by source, session, and entity.

- List: severity, status, **Actor attribution** (AI agent / human / scanner, and so on), AI score
- Detail: attack stage (kill chain: reconnaissance → initial access → …), LLM triage (summary, rationale, recommended response actions),
  the "evidence of AI involvement" cited by the LLM, and related alerts. You can set the assignee and update the status.

The server verifies that the evidence (event IDs) included in the LLM triage refers to events that actually exist.

### Events

Search the raw ingested events. You can filter by type, dataset, source IP, host, time range, and keyword (path / User-Agent).

## Intelligence

### Intelligence

Vulnerability information and the results of matching it against your assets. Tabs: **Vulnerabilities** (merged from KEV / EPSS / NVD / JVN / OSV / GHSA),
**Asset matches**, **Advisories** (prioritized advice from the LLM), **News** (RSS), **Web research**
(0-day research by the LLM), **Sources**. For details, see [Vulnerability intelligence](Threat-Intel-en).

### Assets

Register the hosts you need to protect and the software running on them (product name, version, CPE). Registered assets are used for matching
against vulnerability information and for prioritizing incidents (whether a KEV entry applies).

### Rules

- **Detectors**: enable / disable the built-in detectors (web attack signatures, AI behavior, deception, ports, and so on)
- **Sigma rules**: manage rules in Sigma format (25 bundled + any you add)
- **LLM proposals**: rules the LLM proposed based on vulnerability information. **They are not enabled automatically**; you review and adopt them

## Respond

### Response

A list of response actions proposed by the LLM, rules, and users. Tabs: **Awaiting approval** / **Active** / **History**.
Users with `analyst` or higher can approve, reject, and revert. For details, see [Response (approval workflow)](Response-en).

### Deception

Manage decoys, honeytokens, AI canaries, and labyrinths, and view the records of anything that touched them (trips).
You can also preview what is served. For details, see [Deception (Mirage)](Deception-en).

## System

### LLM

- **Settings**: provider, models (fast / deep; a dropdown for Anthropic), daily budget, output language, API key (write-only). Includes a **Connection test** button
- **Usage**: daily cost, number of calls, and token counts (by purpose)
- **Call log**: an audit log of every LLM call. Admins can also see the redacted input and response bodies

For details, see [LLM setup & cost](LLM-en).

### Settings (admins only)

**Users**, **API tokens** (for sensors; shown only once when created), **Notifications** (Webhook / Slack / Discord / email),
**System** (status of the version, environment, DB, and LLM provider; detectors; list of background jobs and manual runs).
