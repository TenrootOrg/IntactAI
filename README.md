# Intact.AI Security Platform

A comprehensive security platform integrating Velociraptor EDR, ELK Stack, TimeSketch, IRIS, and custom management tools.

## License

Intact.AI is licensed under the **GNU Affero General Public License v3.0
(AGPL-3.0)**. See [LICENSE](./LICENSE) for the full license text.

> If you run a modified version of this software as a network service
> (e.g. accessible to remote users), AGPL-3.0 requires you to offer the
> source of your modifications to those users.

## Notice

**This version is a modified version of the original code.** Intact.AI is
built on top of and incorporates code from several upstream open-source
projects, including (but not limited to):

| Upstream project | License |
|---|---|
| [Velociraptor](https://github.com/Velocidex/velociraptor) | AGPL-3.0 |
| [Timesketch](https://github.com/google/timesketch) | Apache-2.0 |
| [Plaso](https://github.com/log2timeline/plaso) | Apache-2.0 |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web) | LGPL-3.0 |
| [DFIR-O365RC](https://github.com/ANSSI-FR/DFIR-O365RC) | GPL-3.0 |
| [DetectRaptor](https://github.com/mgreen27/DetectRaptor) | Apache-2.0 |
| [Sigma rules](https://github.com/SigmaHQ/sigma) | DRL-1.1 |
| [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Apache-2.0 |

The versions of these projects shipped here have been modified for
integration into the Intact platform. Full attribution and per-component
license details are recorded in [NOTICE](./NOTICE). Refer to each
upstream project's repository for the unmodified original.

## Requirements

- **OS:** Ubuntu 24.04 LTS
- **RAM:** 16GB minimum (32GB recommended)
- **CPU:** 4+ cores
- **Disk:** 100GB+ available space
- **Network:** Static IP address

## Quick Start

```bash
# 1. Clone the repo (gets the latest `main`)
git clone https://github.com/TenrootOrg/IntactAI.git intact
# To install a specific release instead, add `--branch <tag>`,
# e.g.:
# git clone --branch intact-20260609 https://github.com/TenrootOrg/IntactAI.git intact
# Or to track the development branch (latest, unreleased changes):
# git clone --branch development https://github.com/TenrootOrg/IntactAI.git intact

cd intact

# 2. Edit configuration (set your IP/domain and passwords)
nano config.yaml

# 3. Run installer
sudo bash install.sh
```

## Services

Everything terminates TLS through the main nginx. Access is `https://YOUR_IP`
unless a port is listed. `install.sh` starts containers only for enabled
modules.

| Module | What it does | Access | Containers |
|---|---|---|---|
| **Dashboard** | Web UI — workflows, blueprints, reports, settings | `/` | `intact_backend`, `intact_tusd`, `intact_nginx` |
| **Velociraptor** | Endpoint forensics + remote collection | `/velociraptor/` (proxied — not the upstream port) | `intact_velociraptor` |
| **TimeSketch** | Timeline analysis — ingests Plaso super-timelines, pivots across hosts from one view | `:5000` | `intact_timesketch_web`, `_web_v3`, `_web_legacy`, `_worker`, `_nginx`, `_postgres`, `_redis`, `_opensearch` |
| **ELK** | Searchable log store + Kibana. Indexes Velociraptor hunts and Sigma matches | `:5601` | `intact_elasticsearch`, `intact_logstash`, `intact_kibana` |
| **IRIS** | Case management — incidents, assignees, evidence chains, runbook progress | `:8443` | `intact_iris_app`, `_db`, `_worker`, `_rabbitmq`, `_nginx` |
| **VolWeb** | Memory forensics (Volatility 3 + YARA) | `:8002` | `intact_volweb_frontend`, `_backend`, `_workers`, `_workers_yarascan`, `_postgresdb`, `_redis` |
| **Portainer** | Container management — inspect, restart, tail logs | `:9443` | `intact_portainer`, `intact_portainer_agent` |
| **Case Analysis (Fusion)** | Correlates every host + module into one incident graph → fused report, advisory, timeline, Identities, and grounded chat | in Dashboard | — |
| **Memory** | Remote acquisition (AVML / WinPmem), analysed in the VolWeb stack | in Dashboard | — |
| **Cloud DFIR** | AWS **CloudTrail** and Microsoft 365 / Azure AD **(DFIR-O365RC)** collection + SIGMA detections | in Dashboard | in `intact_backend` |
| **Plaso** | Super-timeline generation | via TimeSketch | image pulled per job |
| **Scheduler / Blueprints / Agentic** | Scheduled collections, reusable blueprints, agentic quick-wins | in Dashboard | — |

> The search engines — TimeSketch's OpenSearch and ELK's Elasticsearch/Kibana —
> are the biggest RAM/CPU consumers. On a small host, `docker stop` the stacks
> you are not using.

## Configuration

Edit `config.yaml` before installation:

```yaml
domain: 192.168.1.96  # Your server IP or domain

modules:
  # On-prem forensics (each has its own container + UI)
  velociraptor:
    enabled: true
    id: admin
    password: 'your-password'
  timesketch:
    enabled: true
    id: admin
    password: 'your-password'
  elk:
    enabled: true
    id: elastic
    password: 'your-password'
  iris:                 # id is fixed to 'administrator'
    enabled: true
    password: 'your-password'
  volweb:               # memory forensics (Volatility 3 + YARA)
    enabled: true
    id: admin
    password: 'your-password'
  portainer:
    enabled: false
    id: admin
    password: 'your-password'

  # Feature modules (run in the backend / on-demand — no dedicated container)
  plaso:                # log2timeline timeline engine (on-demand image)
    enabled: true
  cloudtrail:           # AWS CloudTrail DFIR — ships OFF until validated
    enabled: false
  o365rc:               # Microsoft 365 / Azure AD DFIR (DFIR-O365RC)
    enabled: false

versions:               # main module pins (sub-component pins also live here)
  velociraptor: 0.77.1
  velociraptor_legacy: '0.7.1'   # legacy binary for older / Win7 endpoints
  timesketch: '20260617'
  elk: 9.4.2
  iris: 'v2.4.27'
  volweb: '3.16.0'
  portainer: 2.39.1
  plaso: '20260512'
  cloudtrail: '2026.04'
```

## Network / Firewall Ports

| Port | Direction | What it carries |
|---|---|---|
| **443** | in + out | **In:** Dashboard, `/velociraptor/`, `/api/` — the main one. **Out:** install (Docker Hub, GitHub, Ubuntu apt, PyPI) and, per enabled module, LLM providers / `*.microsoftonline.com` + `graph.microsoft.com` / `*.amazonaws.com` / GitHub for YARA. Outbound is skippable if you install and upgrade from packages. |
| **8000** | in | **Required.** Velociraptor agents phone home here. Blocked, and agents silently never appear in the Clients list. |
| **80** | in | HTTP → HTTPS redirect |
| **5000 · 5601 · 8002 · 8443 · 9443** | in | TimeSketch · Kibana · VolWeb · IRIS · Portainer. Lock these to the analyst subnet. |

**Minimum viable:** 443 in from analysts, 8000 in from endpoint subnets, 443 out
during install. Everything else is opt-in per module.

## Upgrades

One release at a time (N → N+1). Each hop is tested as a single step; skipping
releases is not.

Four routes, all the same engine underneath (`scripts/upgrade.sh`):

| Route | Where | Use it when |
|---|---|---|
| **Online Upgrade** | Dashboard → Settings | The box can reach GitHub |
| **Prepare Package** | Dashboard → Settings | Build one file to carry to an air-gapped box |
| **Import Package** | Dashboard → Settings | Apply a package you carried in |
| **CLI** | shell | Scripted runs, recovery, single-module repair |

```bash
sudo bash scripts/upgrade.sh <tag>                     # online
sudo bash scripts/upgrade.sh --package <file|dir>      # air-gap
sudo bash scripts/upgrade.sh --package <dir> --dry-run # plan only, changes nothing
sudo bash scripts/upgrade.sh --list                    # what is available

sudo bash scripts/prepare_package.sh <tag>             # build one carry-in file
```

`--only a,b` is taken literally — omitting `intact` upgrades those modules
against the current platform code, which is warned about but allowed, because
repairing one module without moving the platform is a legitimate thing to want
from a shell. The dashboard always includes `intact`. `--reinstall a,b`
re-applies a module already at the target version.

**Release shapes.** `20260811` onward publishes one asset per module plus
`<tag>.index.json` and `<tag>.manifest.json`; `20260810` and earlier publish a
single `intact-upgrade-<tag>.tar.gz`, split into `.part-NN` when large. Both
apply identically — point `--package` at a directory of assets, a single file,
or repeat the flag.

**Host dependencies are reported, never applied.** The engine runs inside a
helper container, so installing `docker-ce` would restart the daemon and kill
the run mid-flight. An upgrade tells you when the host is behind the release;
apply it yourself:

```bash
sudo bash scripts/update_host_deps.sh --package <release dir>   # --dry-run first
```

**What survives.** Data volumes and per-box state survive an upgrade. Files no
package can ship — `modules/*/secrets/*.env`, TLS certificates — are generated
when missing. Downgrades are refused outright, with no `--force`.

## Scripts

### Module Repair

```bash
# Check status of all modules
sudo bash scripts/repair_modules.sh

# Repair all failed modules
sudo bash scripts/repair_modules.sh --repair-failed

# Repair a specific module
sudo bash scripts/repair_modules.sh elk
```

Available modules: `elk`, `timesketch`, `velociraptor`, `iris`, `portainer`, `backend`, `nginx`

### Change Platform IP

Repoint an already-installed platform to a new IP (e.g. after moving the
VM to a different network). `config.yaml`'s `domain:` is the single
source of truth; this script updates it and re-runs the same propagation
the installer uses, then recreates/restarts the affected containers.

```bash
# Change the platform IP (always non-interactive — never prompts)
sudo bash scripts/change_ip.sh 192.168.120.11

# Re-run with the CURRENT IP to REPAIR a broken state
# (re-applies config, regenerates certs, recreates/heals the module
#  containers). This is the fix when a UI is down after an IP change.
sudo bash scripts/change_ip.sh "$(grep -E '^domain:' config.yaml | awk '{print $2}')"
```

> The script always runs **force + non-interactive**: it never asks for
> confirmation, and it re-applies the full pipeline **even when the IP is
> unchanged**. `-y`/`--yes` is still accepted but is now a no-op. This is
> deliberate — `change_ip.sh` doubles as the platform **repair** tool.

It sets `domain:`, re-propagates the IP, regenerates the TLS certificates and
Velociraptor configs, refreshes nginx, and rebuilds the client installers.
Idempotent and safe to re-run after an interruption — which is what makes it a
repair tool.

> **Note:** Velociraptor agents already deployed on endpoints have the
> old server IP baked in and will **not** reconnect. Redeploy those
> endpoints with the freshly generated installers in `client_installers/`,
> or keep the old IP reachable as an alias. Browser TLS warnings are
> expected (self-signed certificate).

### Clean/Uninstall

To remove Intact.AI components (containers, volumes, data):

```bash
sudo bash scripts/clean.sh                 # interactive
sudo bash scripts/clean.sh --all --force   # full uninstall, no prompts
```

Scopes: `--all`, `--containers`, `--volumes`, `--images`, `--data`, `--logs`.

---

### Updating the Velociraptor artifact bundle

~400 curated artifacts (Artifact Exchange / DetectRaptor / Sigma / Rapid7 /
Triage / TenRoot) are committed in `modules/velociraptor/bundled_artifacts/`,
baked into the velociraptor image and loaded on boot via `--definitions`, so
they are present the instant Velociraptor starts — install, upgrade or
air-gapped apply alike. Refresh the snapshot when you want upstream changes,
typically once per release:

```bash
# On a box with a RUNNING Velociraptor + internet (the dev/build host):
docker exec intact_backend python \
    /app/workdir/modules/backend/scripts/regenerate_artifact_bundle.py

# Review the diff, then commit the refreshed bundle:
git add modules/velociraptor/bundled_artifacts
git commit -m "Refresh Velociraptor artifact bundle"
```

It runs the upstream import artifacts (plus DetectRaptor and Extras) and
re-exports every non-built-in artifact. The new bundle takes effect the next
time the velociraptor image is rebuilt.

> Forensic **tools** (Hayabusa, KAPE/EZ tools, YARA, etc.) are delivered
> separately via the tool-inventory download path — see the `download_tools`
> option in `config.yaml`. This bundle ships artifact *definitions* only.
