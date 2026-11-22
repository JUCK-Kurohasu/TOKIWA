> 🌐 [日本語](Response) · **English** · [中文](Response-zh) · [Español](Response-es)

# Response (approval workflow)

When TOKIWA finds a threat, it **proposes** response actions, but **it executes nothing until a human approves**.
Every block has an expiry (TTL) and can be reverted.

## Lifecycle

```
proposed ──approve──▶ approved ──execution succeeds──▶ active ──expires──▶ expired
    │                       │                             └──revert──▶ reverted
    └──reject──▶ rejected   └──execution fails──▶ failed
```

| Operation | Who | Notes |
|---|---|---|
| Propose | LLM (triage) / rules / users | If a proposal of the same type for the same target already exists, the reason is appended to it instead of creating a new one |
| Approve / reject | `analyst` or higher | Approving executes the action immediately |
| Revert | `analyst` or higher | Actions that are `active` and revertible |
| Expire | Automatic (checked every 30 seconds) | Lifted once the TTL has passed |

Every operation is recorded in the audit log.

## Response action types

| Type | Target | What happens |
|---|---|---|
| `block_ip` | IP / CIDR | The Gate returns 403 to that source |
| `rate_limit` | IP / CIDR | The Gate limits requests per minute (default 60). Over the limit, it returns 429 |
| `tarpit` | IP / CIDR | The Gate delays responses (default 2,000 ms, max 30 seconds) |
| `deceive` | IP / CIDR | The Gate turns every response to that source into a decoy |
| `nftables_block` | Single IP | Adds the IP to a set in the host's nftables (**disabled by default**) |
| `deploy_canary` | Path | Deploys a deception asset (decoy, honeytoken, AI canary) |
| `notify` | — | Sends to notification channels |
| `webhook` | — | Sends fixed-format JSON to a configured webhook |

Response actions that involve the Gate take effect the next time the Gate pulls its policy (within 5 seconds by default).
**An approved action shown as "Active" is not enforced until a Gate pulls the policy.** It also only affects requests that pass through a Gate;
paths that bypass the Gate (log-ingestion-only setups, direct access around the Gate) are not blocked.

Each card on the Response screen shows whether a Gate has applied the action.

| Display | Meaning |
|---|---|
| No Gate to apply it | No Gate has pulled the policy. The action is not enforced |
| Approved (not applied yet) | There is a Gate, but it has not pulled the policy since the approval |
| Applied by n Gate(s) (hh:mm) | The number of Gates that pulled the policy after the approval, and the latest pull time |
| … none has polled for over N min | Applied, but those Gates have stopped pulling the policy (they may be down) |

The "Active" tab also shows the overall Gate status (how many Gates are pulling, which ones stopped). A Gate counts as stopped after
`max(120 s, gate.policy_refresh_seconds × 12)` without a pull. The same information is available from `GET /api/v1/gate/status`.
Gates are told apart by "token + source address", so several Gates behind one reverse proxy count as one.

## Safeguards

1. **Nothing executes without approval**. The executor accepts only approved rows (with the approver and approval time).
   This is guaranteed by tests (every action type × every proposal source, concurrent approvals, static checks of the code).
2. **Free-form LLM text never reaches anything that executes**. The executor receives only the validated type, normalized IP / CIDR, typed parameters, and TTL.
   No shell command strings are built.
3. Proposal validation rejects targets such as:
   - Anything that cannot be parsed as an IP / CIDR (hostnames, anything containing `;`, and so on)
   - Ranges that are too broad (broader than /16 for IPv4 or /48 for IPv6, such as `0.0.0.0/0`)
   - Anything that overlaps the **protected ranges** (`response.protected_cidrs`; default `127.0.0.0/8`, `::1/128`)
   - The server's own IP addresses (`response.protect_server_addresses`, on by default)
4. Right before execution, the action is **validated again** against the current settings (for example, if you added a protected range after the proposal, it becomes `failed`).
5. **Active actions are re-checked against the current settings too.** An action that falls in a range you later added to `response.protected_cidrs` (or similar) is dropped from the policy on the Gate's next pull and becomes `reverted` within 30 seconds (or at restart), with `response.auto_revert` in the audit log.

> 💡 We strongly recommend adding the IPs of admin workstations, monitoring systems, and upstream load balancers to `response.protected_cidrs`.

## TTL (validity period)

- Default 60 minutes (`response.default_ttl_minutes`), max 7 days (`response.max_ttl_minutes`). Values above the max are truncated.
- When the TTL is reached, the action is lifted automatically.

## Auto-approval (off by default)

You can skip approval for specific action types only. It works only when you enable **both settings**.

```yaml
response:
  auto_approve_enabled: true
  auto_approve_actions: ["rate_limit", "tarpit"]   # Only the types listed here
```

The approver of an auto-approved response action is recorded as `policy`. Think carefully before auto-approving blocks (`block_ip`), because false positives have a large impact.

> "Two-person approval", which requires the proposer and the approver to be different people, is not yet enforced in v0.1 (planned as a setting in the next development phase).

## Reject, revert and suppression (stopping re-proposals)

The reject and revert dialogs let you choose what happens to "re-proposals for this target".

| Choice | Rule / LLM proposals of the same type for the same target | Auto-approval |
|---|---|---|
| Don't suppress (default) | Still proposed | **Not for 24 hours** (`response.auto_approve_cooldown_minutes`, 0 disables) |
| Don't re-propose for N hours / never | **Not created** (`response.propose_suppressed` in the audit log; no approval-request notification either) | No |

- IP / CIDR targets match by overlap (an IP inside a suppressed /24, or a broader CIDR containing a suppressed IP, also matches). A different action type is treated separately.
- A proposal a human makes manually is still created while suppressed (it is never auto-approved).
- List and lift suppressions on the **Suppressions** tab of the Response page (API: `GET /api/v1/response/suppressions`, lift with `POST /api/v1/response/suppressions/{id}/lift`).
- To suppress a shared NAT or monitoring-service IP in advance, use `POST /api/v1/response/suppressions`.

## Blocking with nftables (optional)

Use this when you also want to stop traffic that does not go through the Gate. It is **disabled by default**, and it always fails unless you enable it.
TOKIWA does not create tables, sets, or rules; it only adds and removes elements in a set, so an administrator must prepare them beforehand.

```bash
nft add table inet tokiwa
nft add set inet tokiwa blocklist  '{ type ipv4_addr; flags timeout; }'
nft add set inet tokiwa blocklist6 '{ type ipv6_addr; flags timeout; }'
nft add chain inet tokiwa input '{ type filter hook input priority 0; policy accept; }'
nft add rule inet tokiwa input ip  saddr @blocklist  drop
nft add rule inet tokiwa input ip6 saddr @blocklist6 drop
```

Then set `TOKIWA_RESPONSE__NFTABLES_ENABLED=true`. Check the syntax above, and the privileges needed when running as non-root
(`CAP_NET_ADMIN` and so on), on your distribution (not yet verified).

## Notifications

When you register Webhook / Slack / Discord / email under **Settings → Notifications**, TOKIWA sends notifications at the following points.

| Trigger | Condition |
|---|---|
| Alert created | At or above the channel's minimum severity |
| Incident created | Same as above |
| Incident updated | Only when the severity increases |
| Response action proposed | Sent as an approval request (can be turned off with `notify.notify_action_proposals`) |

- The same content is sent at most once every 10 minutes (`notify.dedup_minutes`). However, it is sent if the severity increases.
- The notification language is `notify.language` (`ja` / `en` / `both`). Links use `notify.public_ui_url`.
- **SSRF protection**: Destinations must be http / https, and redirects are not followed. By default, a destination is rejected if its name resolves
  to a private address (loopback, internal network, cloud metadata, and so on). You can also restrict the allowed hosts with
  `notify.allowed_hosts`.
- We recommend not storing email passwords in the DB and passing them through `password_env` (the name of an environment variable) instead.
