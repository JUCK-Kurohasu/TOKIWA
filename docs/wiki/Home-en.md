> 🌐 [日本語](Home) · **English** · [中文](Home-zh) · [Español](Home-es)

# TOKIWA Wiki

**TOKIWA (常磐)** is an **LLM-driven SIEM / XDR** that detects and defends against cyberattacks carried out by generative AI (LLM agents).
It is built as the defensive (Blue) counterpart to **ARTEX**, an autonomous AI penetration testing system.

> ⚠️ **In development (v0.1.0)**. It is intended for use in labs and in environments that you manage or are authorized to test.

## What TOKIWA does

On top of the "attacks that match a signature" that traditional SIEMs handle well, TOKIWA focuses on recognizing **behavior typical of AI agents**.

| Aspect | Example |
|---|---|
| Thinking-pause rhythm | Bursts of parallel tool calls alternate with "pauses" while the model waits on inference |
| Adapting after errors | Right after receiving a 500 or 403, it retries with the payload changed bit by bit |
| Semantic exploration | It discovers unlinked APIs from JS bundles and OpenAPI and calls them |
| Following hidden instructions | It follows "instructions that only an AI reads and obeys" embedded in decoys (AI canaries) |

An LLM triages detected alerts with supporting evidence and **proposes** response actions (block, rate limit, and so on).
**They are executed only when a human approves them.**

## How it works (overview)

```
 Attacker / user ──▶ TOKIWA Gate (reverse proxy) ──▶ Web app you want to protect
                        │  Captures HTTP including bodies; applies blocks, rate limits and decoys instantly
                        ▼
                 TOKIWA Server (API + Web UI)
                   Ingest → detect (signatures, Sigma, AI behavior) → correlate (into incidents)
                   → LLM triage → propose response actions → human approves → applied at the Gate
                   + Vulnerability intelligence (KEV / EPSS / NVD / OSV / JVN / GHSA / RSS)
                   + Deception (decoys, honeytokens, AI canaries)
                   + SOC Copilot (conversation using read-only tools)
                        ▲
 TOKIWA Agent (host) ── ports, connections, nginx / Caddy / Suricata / Zeek logs
```

## Where to start

| What you want to do | Page |
|---|---|
| Just get it running (10 minutes) | [Quick start](Quick-Start-en) |
| Run it day to day with Docker, or closer to production | [Installation & operations](Installation-en) |
| Monitor your own web apps and servers | [Connecting sensors](Sensors-en) |
| Learn how to read the screens | [Web UI guide](Web-UI-en) |
| Set up the LLM (API key, cost, models) | [LLM setup & cost](LLM-en) |
| Approve and operate response actions such as blocks | [Response (approval workflow)](Response-en) |
| Use decoys and AI canaries | [Deception (Mirage)](Deception-en) |
| Match 0-day and vulnerability information against your assets | [Vulnerability intelligence](Threat-Intel-en) |
| Test with the attack simulator or ARTEX | [Lab & evaluation](Lab-and-Evaluation-en) |
| Look up settings and commands | [Configuration reference](Configuration-en) / [CLI reference](CLI-en) |
| Something isn't working | [Troubleshooting](Troubleshooting-en) |

## Safety policy

TOKIWA is a tool for defense. It keeps the following commitments through its design and tests.

1. **Logs passed to the LLM are always treated as "untrusted data"**. They are isolated and redacted before they are passed, so that the LLM does not follow instructions an attacker planted in the logs (prompt injection).
2. **LLM output is never wired directly to anything that executes**. The LLM can only produce "response action types on the allowlist" and "validated IP / CIDR / TTL values"; it is never allowed to produce command or configuration strings.
3. **Response actions require human approval by default**. Auto-approval is limited to the action types for which two settings have been explicitly enabled. Every block has an expiry (TTL) and can be reverted.
4. **Active defense happens only on your own organization's assets** (decoys, labyrinths, tarpits, and so on). TOKIWA never strikes back at the attack source (hack-back).

## Current verification status (v0.1.0)

| Item | Status |
|---|---|
| Backend automated tests (about 1,280), frontend build, Docker image build and smoke test | ✅ Run continuously in CI |
| Local end-to-end run (attack simulator → Gate → detection → incident → approval → Gate returns 403 → revert) | ✅ Verified (mock LLM) |
| Triage quality and cost with a real LLM (Claude) | ⏳ Not yet evaluated |
| Starting the Docker lab with `lab/compose.yaml` | ⏳ Not yet verified |
| Fetching real data from the vulnerability feeds | ⏳ Not yet verified (tested with test data based on the specifications) |
| Purple-team exercise against a real ARTEX | ⏳ Not yet conducted |

Detection accuracy figures (precision and recall of the AI verdict, and so on) come from synthetic data and may be lower in real environments.

## License and links

- License: Apache License 2.0 (provisional)
- Repository: [JUCK-Kurohasu/TOKIWA](https://github.com/JUCK-Kurohasu/TOKIWA)
- Developer documentation: `docs/` in the repository (architecture, API contract, design decisions), `AGENTS.md`, `HANDOFF.md`
