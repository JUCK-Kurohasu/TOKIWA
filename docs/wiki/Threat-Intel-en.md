> 🌐 [日本語](Threat-Intel) · **English** · [中文](Threat-Intel-zh) · [Español](Threat-Intel-es)

# Vulnerability intelligence

This feature periodically ingests vulnerability information, matches it against your registered assets, and produces prioritized advice (advisories).
It also uses the LLM's web search to periodically look for reports of 0-days and exploitation.

## Sources

| Source | Content |
|---|---|
| CISA KEV | Catalog of vulnerabilities whose exploitation has been confirmed in the wild |
| EPSS | Estimated probability of exploitation within 30 days |
| NVD | CVE details, CVSS, affected products (CPE) |
| OSV | Vulnerabilities in open-source packages (PyPI, npm, Go, Maven, and so on) |
| JVN | Japanese vulnerability information |
| GitHub Security Advisories (GHSA) | GitHub advisories |
| RSS | JPCERT/CC, IPA, CISA, The Hacker News, BleepingComputer (default) |

- By default, it syncs every 360 minutes (6 hours) (`intel.sync_interval_minutes`).
- Syncing requires **outbound connections** to these services.
- Without an API key, NVD's rate limits are stricter. GitHub is also more reliable with a token.

```bash
export TOKIWA_INTEL__NVD_API_KEY=...       # Optional
export TOKIWA_INTEL__GITHUB_TOKEN=...      # Optional
```

> ⚠️ For JVN, a revamp of MyJVN from April 2026 onward has been announced. Fetching that relies on the old feeds may no longer work, and
> operation with real data is not yet verified.

## How to use it

1. **Register assets**: On the **Assets** page, register the hosts, services, web apps, and LLM apps you need to protect, and the software running on them
   (vendor, product name, version, CPE, OSV ecosystem).
2. **Wait for a sync (or run one manually)**: You can start a sync from **Intelligence → Sources**. You can also run it from the CLI.

   ```bash
   cd backend
   uv run tokiwa intel sync              # All enabled sources
   uv run tokiwa intel sync -s kev       # Only a specific source
   uv run tokiwa intel status            # Sync status per source
   uv run tokiwa intel show CVE-2021-44228
   ```

3. **Look at the results**: Check the tabs on the **Intelligence** page.

| Tab | Content |
|---|---|
| Vulnerabilities | Data from all sources merged per CVE (KEV listing, EPSS, CVSS) |
| Asset matches | Vulnerabilities that match your assets' software. You can track their status (open / addressed, and so on) |
| Advisories | Prioritized advice from the LLM. Generated with priority given to KEV listings, high EPSS, and asset matches |
| News | RSS articles |
| Web research | Results of the LLM's research into 0-days and exploitation reports. You can also run it manually for a topic you specify |
| Sources | Last sync and item count for each source |

## Advisories and detection rule proposals

In addition to an impact summary, a priority, and recommended actions, an advisory may include a **draft detection rule in Sigma format**.
Draft rules are validated and then saved as "proposals" under **Rules → LLM proposals**; **they are not enabled automatically**.
A human reviews and adopts them.

## Integration with incidents

If an alert references a CVE and that CVE is listed in KEV, the incident's priority is raised.
On the Dashboard, "KEV matches" is the number of matches between known exploited vulnerabilities and your assets.

## Web research (periodic 0-day research)

- By default, every 12 hours (`intel.research_interval_hours`), it researches the topics in `intel.research_topics`.
- It uses Claude's **server-side web search**, so it actually searches **only when an Anthropic API key is set**.
  With the mock LLM, no search is performed, and the results say so.
- It uses the deep model, so it incurs LLM costs. If you don't need it, you can turn it off with `intel.research_enabled: false`.
- The result summaries are LLM output. Always check the sources before making important decisions.

## Main settings (`intel.*`)

| Key | Default | Description |
|---|---|---|
| `enabled` | true | Intelligence as a whole |
| `sync_interval_minutes` | 360 | Sync interval |
| `sources` | All true | Enable / disable per source (`kev`, `epss`, `nvd`, `osv`, `jvn`, `ghsa`, `rss`) |
| `rss_feeds` | 5 feeds | RSS URLs to ingest |
| `research_enabled` / `research_interval_hours` | true / 12 | Web research |
| `research_topics` | 2 topics: 0-days and AI-driven attacks | Research topics |
| `epss_alert_threshold` | 0.1 | Threshold for treating an EPSS increase as a sharp rise |
| `nvd_lookback_days` | 3 | Number of days to look back when fetching from NVD |
