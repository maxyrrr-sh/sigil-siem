# Sigil SIEM — native Ubuntu 24.04 deployment (Ansible)

Deploys the **full stack directly on a host** (no Docker) via systemd services,
with configs under `/etc` and data under `/var/lib` — a conventional production
layout.

```
                          Internet
                             │ 443/80
                     ┌───────▼────────┐
                     │     nginx      │  TLS termination + reverse proxy
                     │  /var/www/sigil│  (serves the Svelte SPA)
                     └───┬────────┬───┘
              /api/, SSE │        │ /
              ┌──────────▼──┐  static SPA
              │    sigil    │  core SIEM (systemd) — API on 127.0.0.1:8080,
              │  /etc/sigil │  syslog ingest on :5514 (udp+tcp)
              └──┬───┬───┬──┘
      S3 cold ┌──▼┐ ┌▼──┐ ┌▼──────────┐
              │min│ │red│ │ ml-sidecar│  gRPC embeddings/scoring (127.0.0.1:50051)
              │io │ │pan│ └───────────┘
              └───┘ │da │  Kafka bus (127.0.0.1:9092)
                    └───┘
     prometheus (127.0.0.1:9090)  +  grafana (127.0.0.1:3000)   [monitoring]
```

## Components (all native systemd units)

| Service      | Unit             | Source                              | Listens |
|--------------|------------------|-------------------------------------|---------|
| Sigil core   | `sigil`          | `.deb` (cargo-deb, `--features s3`) | 127.0.0.1:8080, :5514 syslog |
| Frontend     | (served by nginx)| prebuilt `frontend/dist`            | via nginx |
| nginx edge   | `nginx`          | apt                                 | :80, :443 |
| ML sidecar   | `sigil-ml`       | Python venv (`/opt/sigil/ml-sidecar`) | 127.0.0.1:50051 |
| MinIO        | `minio`          | official binary                     | 127.0.0.1:9000/9001 |
| Redpanda     | `redpanda`       | Redpanda apt repo                   | 127.0.0.1:9092 |
| Prometheus   | `prometheus`     | apt                                 | 127.0.0.1:9090 |
| Grafana      | `grafana-server` | Grafana apt repo                    | 127.0.0.1:3000 |

Only nginx (80/443) and the syslog ingest port (5514) are host-facing;
everything else binds loopback.

## Filesystem layout

```
/etc/sigil/sigil.yaml        core config (0640 root:sigil, secrets baked in)
/etc/sigil/sigil.env         AWS_* creds for the S3 cold tier
/etc/sigil/rules/            Sigma detection + correlation rules
/etc/sigil/tls/              nginx TLS cert + key
/etc/redpanda/redpanda.yaml  bus config
/etc/default/minio           MinIO env
/etc/prometheus/…            scrape config
/etc/grafana/…               grafana.ini + datasource provisioning
/var/lib/sigil/              events, index, cold segments, catalog, alerts
/var/lib/minio/data          object store
/var/www/sigil/              built SPA
/opt/sigil/ml-sidecar/       sidecar venv + code
```

## Prerequisites

- **Control node**: Ansible ≥ 2.16, `rsync`, SSH access to the target as a sudo user.
- **Target**: a fresh **Ubuntu 24.04** host with outbound internet.

```bash
cd deploy/ansible
ansible-galaxy collection install -r requirements.yml
cp inventories/inventory.yaml.example inventories/inventory.yaml   # set ansible_host, ansible_user, domain
```

## Deploy

```bash
ansible-playbook site.yml
```

That's it — one command brings up the whole stack, generates all secrets, hashes
the admin password, writes the config, and starts every service. Re-running is
idempotent (secrets and the argon2 hash are cached under `./credentials/`).

### The sigil `.deb`

By default the playbook **builds the `.deb` from this repo's source on the
target** (installs rustup + `cargo-deb`, syncs the source, runs
`cargo deb -p sigil-cli -- --features s3`). This compiles the workspace, so the
first run takes a while and needs a few GB of RAM/disk.

For a "deploy a released artifact" flow, skip the build:

```bash
ansible-playbook site.yml \
  -e build_from_source=false \
  -e sigil_deb_url=https://your-artifacts/sigil_0.0.0_amd64.deb
# …or a .deb already on the control node:
ansible-playbook site.yml -e build_from_source=false -e sigil_deb_local_path=./sigil.deb
```

## Secrets & credentials

Generated once and cached (git-ignored) under `deploy/ansible/credentials/` on
the **control node**:

| File                  | What |
|-----------------------|------|
| `sigil_admin`         | admin console password |
| `sigil_admin_hash`    | its argon2 hash (baked into the config) |
| `jwt_secret`          | API JWT signing secret |
| `minio_root_password` | MinIO root / S3 secret key |
| `grafana_admin`       | Grafana admin password |

Back this directory up securely; deleting a file causes that secret to be
regenerated on the next run.

## Access

- **Console / API**: `https://<domain>/` (self-signed TLS by default — provide
  `-e tls_cert_src=… -e tls_key_src=…` for a real cert).
- **Login**: `admin` / the value in `credentials/sigil_admin`.
- **Syslog ingest**: point sources at `udp/tcp <host>:5514` (RFC 5424).
- **Grafana / Prometheus / MinIO console**: loopback only — reach via SSH tunnel,
  e.g. `ssh -L 3000:127.0.0.1:3000 user@host`.

## Common overrides

```bash
# skip monitoring, rebuild the SPA on the host, custom retention:
ansible-playbook site.yml \
  -e install_monitoring=false \
  -e frontend_build=true \
  -e retention_hot=14d -e retention_cold=180d
```

## Day-2

```bash
# on the host
systemctl status sigil
journalctl -u sigil -f
sigil config validate /etc/sigil/sigil.yaml
```

Editing `/etc/sigil/sigil.yaml` and `systemctl restart sigil` applies changes;
re-running the playbook reconciles everything back to declared state.
