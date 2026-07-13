# Sigil EDR — endpoint detection & response

Sigil is a SIEM that **consumes** telemetry; `docs/DESIGN.md` §1 lists "not an
EDR agent" as a non-goal. The EDR module is an **optional companion** that adds
first-party endpoint collection + response without changing that identity: the
SIEM core still only consumes events — the collection lives in a separately-built
agent, and the server side is a normal ingest source.

## Components

| Piece | Crate | Default build? |
|---|---|---|
| Wire contract (gRPC, `proto/sigil_edr.proto`) | `sigil-edr-proto` | yes |
| Server gateway: enrollment, fleet registry, command queue, telemetry→`Event` | `sigil-edr` | yes |
| Endpoint agent: collectors + response executors | `sigil-agent` | **no** (opt-in) |

`sigil-agent` is excluded from `default-members` (like `sigil-correlate-rl`), so
`cargo build` and CI never pull its platform deps (`sysinfo`, `notify`,
`netstat2`). Build it explicitly:

```bash
cargo build -p sigil-agent
```

## Protocol (`package sigil.edr.v1`)

- `Enroll(EnrollRequest) → EnrollReply` — one-time. The agent presents a
  pre-shared **enrollment token** and receives a server-assigned `agent_id` +
  `session_token`.
- `Session(stream AgentMessage) ⇄ stream ServerMessage` — a long-lived
  bidirectional stream. Agent → server: `Hello`, `Heartbeat`, `TelemetryBatch`,
  `CommandResult`. Server → agent: `HelloAck`, `Command`, `HeartbeatAck`.

Endpoint telemetry (`EndpointEvent`) is mapped to the normalized
`sigil_core::Event` in `sigil-edr/src/map.rs`, so it flows through the **existing**
Sigma / index / correlation pipeline unchanged. New OCSF classes were added for
endpoint telemetry: `DnsActivity`, `ModuleActivity`, `ScheduledJobActivity`,
`RegistryKeyActivity` (plus existing Process/File/Network).

## Server setup

Enable the gateway on a node holding the `index` role (`configs/sigil.yaml`):

```yaml
edr:
  enabled: true
  listen: 0.0.0.0:50055
  tls_cert: /etc/sigil/edr-cert.pem   # recommended (plaintext otherwise, with a warning)
  tls_key: /etc/sigil/edr-key.pem
  enrollment_tokens: ["<pre-shared-token>"]
```

Agents, commands, and enrollment tokens persist in the `sigil-store` (redb) at
`data_dir` as saved objects (`edr-agent`, `edr-command`, `edr-token`).

## Agent setup

See `configs/agent.example.yaml`.

```bash
sigil-agent enroll --config agent.yaml   # persists agent_id + session_token
sigil-agent run    --config agent.yaml   # collect → stream → respond
```

Portable collectors (cross-platform): **process** (snapshot-diff via `sysinfo`),
**file** (FIM via `notify`), **network** (active connections via `netstat2`),
**persistence** (autostart-location inventory). Native fast paths (eBPF/ETW/
EndpointSecurity) are a later phase behind the same `Collector` trait.

## Response actions

Queued via the API and delivered over the live stream; every command + result is
persisted as an audit record.

| Action | Effect |
|---|---|
| `kill_process` | Kill a process by pid |
| `quarantine_file` | Move a file to the quarantine dir, strip its permissions (reversible via a `.meta.json` sidecar) |
| `isolate_host` / `unisolate_host` | Host firewall isolation (nftables/pf/Windows Firewall). The Sigil control channel + loopback are **always** allowlisted, so isolation can never sever the agent |
| `fetch_file` | Retrieve a file (bounded) for triage |

No remote shell (by design — keeps the RCE surface small).

## Control surface

REST (`/api/v1/edr/*`, JWT + RBAC):

- `GET  /edr/agents`, `GET /edr/agents/{id}` — fleet + detail (any authenticated role)
- `POST /edr/agents/{id}/actions` — enqueue a response action (**analyst**)
- `GET  /edr/commands` — command audit trail
- `GET/POST /edr/enroll-tokens` — manage enrollment tokens (**admin**)
- `GET  /edr/stream/agents` — SSE fleet status

CLI (thin HTTP clients over the API):

```bash
sigil edr agents
sigil edr agent <id>
sigil edr action <agent> kill_process --pid 1234
sigil edr action <agent> quarantine_file --path /tmp/x
sigil edr action <agent> isolate_host
sigil edr commands --agent <id>
sigil edr token --label field
```

UI: the **Agents** page (Respond group) in the Svelte console — fleet list, live
status (SSE), agent detail, command history, and action buttons with confirmation.

## Detections

Endpoint Sigma rules ship in `configs/rules/edr/` (10 rules: suspicious process
lineage, web-shell exec, credential-file access, download-piped-to-shell, reverse
shell, cron/systemd + Run-key persistence, temp-path module load, long DNS query,
LOLBins). Plus an **IOC-matching detector** (`detect:ioc`) that matches
hash/IP/domain indicator lists against telemetry:

```yaml
detectors:
  - ioc:
      hashes: ./iocs/hashes.txt   # file (one/line) or an inline list
      ips: ./iocs/ips.txt
      domains: ./iocs/domains.txt
```

## Security notes

- **Transport**: TLS with a pinned CA is the intended default; loopback plaintext
  is allowed for dev only, with a loud warning. Full mTLS (client certs) is a
  follow-up.
- **Response is powerful**: actions are RBAC-gated (analyst+/admin) with a full
  persisted audit trail (who/when/result).
- **Isolation can't self-lock**: the control channel is always allowlisted.

## Later phases

Native collectors (eBPF/aya, ETW, EndpointSecurity), mTLS client certs,
fetch-file chunking, agent auto-update, and a dead-man auto-unisolate.
