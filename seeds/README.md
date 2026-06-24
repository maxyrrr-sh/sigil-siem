# Seed data

Ready-to-use sample logs for exercising the full pipeline — search, Sigma
detection, semantic + causal correlation, and analytics — with no downloads.
All three files describe the **same intrusion** (a brute-force → sudo-to-root →
`/etc/shadow` read → web-shell → exfil on `web01` by user `mallory`) wrapped in
benign noise, so they tell one coherent story across codecs.

| File | Codec | Exercises |
|---|---|---|
| [`linux-auth.log`](linux-auth.log) | `syslog` | file/syslog ingest, OCSF normalization, **Sigma alerts** (T1110.001, T1548.003, T1003.008) |
| [`campaign.jsonl`](campaign.jsonl) | `json` | a clean **cross-domain campaign** (auth → process → http → network) → reconstructed kill-chain |
| [`mixed-traffic.jsonl`](mixed-traffic.jsonl) | `json` | the campaign **buried in benign noise** — correlation surfaces it as the top incident; analytics over all 5 OCSF classes |

## Try it

```bash
# 1) Detection — replay syslog, get ATT&CK-tagged alerts
sigil replay seeds/linux-auth.log --codec syslog
#    → 8 alerts: SSH Failed Password (T1110.001), Sudo→root (T1548.003), /etc/shadow (T1003.008)

# 2) Correlation — reconstruct the cross-domain kill-chain
sigil correlate seeds/campaign.jsonl --codec json
#    → 1 campaign across 4 domains; incident: credential-access → command-and-control

# 3) Needle in a haystack — the attack ranks #0 out of the noise
sigil correlate seeds/mixed-traffic.jsonl --codec json

# 4) Analytics — index the JSON traffic, then query it (SQL or pipe-DSL)
sigil replay seeds/mixed-traffic.jsonl --codec json
sigil query "SELECT ocsf_class_name, count(*) AS n FROM events GROUP BY ocsf_class_name ORDER BY n DESC"
sigil query 'search shell.php | stats count() as hits by host'

# 5) Live tailing — point a file input at a seed and watch it ingest
#    (configure inputs[].type=file, path=seeds/linux-auth.log) then:
sigil run                       # API + UI on http://127.0.0.1:8080/ui
```

> `replay`/`query` write to the index path from `--config` (default
> `configs/sigil.yaml` → `./data`, gitignored). `correlate` only needs the
> Sigma rules from the config for technique tags.

## Generate more

The evaluation harness has a deterministic synthetic scenario generator (pinned
seed → reproducible) used to *measure* correlation/attribution:

```bash
sigil eval --seed 1     # combined vs baselines/ablations: ARI, NMI, chain-sim, …
```

## Real public datasets (to scale up)

These are larger, real-world corpora. Plain-text logs ingest directly with the
matching codec; provenance-graph datasets need a loader (the DARPA/ATLAS loaders
are the deferred Phase 6 item — see `docs/DESIGN.md` §11.1).

| Dataset | What it is | Use with Sigil |
|---|---|---|
| **Loghub** | 16 real system-log corpora (Linux, OpenSSH, Apache, HDFS, …) | `OpenSSH`/`Linux` → `--codec syslog`; great for ingest/template-mining scale |
| **AIT-LDS v2.0** | 8 labelled enterprise testbeds w/ attacks + **ground truth** | auth/syslog → `syslog`; Suricata `eve.json` → `json`; ideal once an eval loader maps its ground truth |
| **EVTX-ATTACK-SAMPLES** | Windows EVTX samples mapped to ATT&CK | convert EVTX→JSONL (e.g. `evtx_dump`/Chainsaw) → `--codec json` |
| **SecRepo / Samples** | curated security log/pcap samples | varies; text logs → `syslog`/`json` |
| **DARPA TC (Transparent Computing)** | host **provenance graphs** (CADETS/THEIA/…) | needs a provenance loader (Phase 6); best fit for the §9 causal-graph feature |
| **ATLAS** | attack-story provenance + ground-truth attack chains | needs a loader; directly targets attribution metrics (chain P/R, GED) |

Sources:
- [Loghub (logpai/loghub)](https://github.com/logpai/loghub) · [OpenSSH subset](https://github.com/logpai/loghub/tree/master/OpenSSH) · [Zenodo mirror](https://zenodo.org/records/8196385)
- [AIT Log Data Set V2.0 (Zenodo)](https://zenodo.org/records/5789064)
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [SecRepo Samples](https://www.secrepo.com/)
- [DARPA Transparent Computing](https://github.com/darpa-i2o/Transparent-Computing)
- [ATLAS](https://github.com/purseclab/ATLAS)
