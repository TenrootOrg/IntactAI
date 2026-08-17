# Intact.AI Security Platform

A comprehensive security platform integrating Velociraptor EDR, ELK Stack, TimeSketch, IRIS, and custom management tools.

## License & Attribution

| Component | License |
|---|---|
| **Intact.AI** — see [LICENSE](./LICENSE) | **AGPL-3.0** |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | AGPL-3.0 |
| [Timesketch](https://github.com/google/timesketch) | Apache-2.0 |
| [Plaso](https://github.com/log2timeline/plaso) | Apache-2.0 |
| [DFIR-IRIS](https://github.com/dfir-iris/iris-web) | LGPL-3.0 |
| [DFIR-O365RC](https://github.com/ANSSI-FR/DFIR-O365RC) | GPL-3.0 |
| [DetectRaptor](https://github.com/mgreen27/DetectRaptor) | Apache-2.0 |
| [Sigma rules](https://github.com/SigmaHQ/sigma) | DRL-1.1 |
| [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) | Apache-2.0 |

**This is a modified version of the upstream projects above**, adapted for
integration into Intact.AI. Full per-component attribution is in
[NOTICE](./NOTICE); refer to each upstream repository for the unmodified
original.

> Running a modified version as a network service obliges you under AGPL-3.0 to
> offer the source of your modifications to its users.

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

### Air-gapped installation

> Supported from `intact-20260813` onward.

`--package` makes the installer take every image and dependency from the file
you carry in, never from a registry.

On a machine with internet:

```bash
git clone --branch <tag> https://github.com/TenrootOrg/IntactAI.git intact
cd intact
bash scripts/prepare_package.sh <tag> /media/usb    # writes intact-upgrade-<tag>.tar
```

Carry **both** the `intact` folder (the one `git clone` made) and the `.tar`
across — `install.sh` lives in that folder. Then on the air-gapped box:

```bash
cd /path/to/intact
nano config.yaml                                    # IP/domain and passwords
sudo bash install.sh --package /media/usb/intact-upgrade-<tag>.tar
```

`--package` is repeatable and also takes a directory of per-module assets. If
Docker is not already installed, carry the release's `<tag>-system-bundle.tar`
too and put it beside the package — it provides the engine and host packages
offline.

## Services & Ports

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


**Firewall.** `443` in from analysts (Dashboard, `/velociraptor/`, `/api/`) and
`8000` in from endpoint subnets — Velociraptor agents phone home on 8000, and if
it is blocked they silently never appear in the Clients list. `80` redirects to
HTTPS. The module ports above should be locked to the analyst subnet.

`443` outbound is used during install and upgrade, and by enabled modules that
call out (LLM providers, Microsoft Graph, AWS). It can be skipped entirely if
you install and upgrade from packages.

## Upgrades

Jump straight to any newer release in one run — each module asset is absolute
("this *is* elk 9.4.4"), so the target's engine moves every module from whatever
the box has directly to target. A 0726 → 0821 single hop, evidence preserved, is
a tested path.

`bootstrap_upgrade.sh` fetches the target release's own engine
(`<tag>-engine.tar.gz`), verifies its sha256, then hands over — so the upgrade is
driven by the release being installed, never by this box's code. Four routes, one
engine:

| Route | Where | Use it when |
|---|---|---|
| **Online Upgrade** | Dashboard → Settings | The box can reach GitHub |
| **Prepare Package** | Dashboard → Settings | Build a file to carry to an air-gapped box |
| **Import Package** | Dashboard → Settings | Apply a package you carried in |
| **CLI** | shell | Air-gapped, scripted, recovery, single-module repair |

The CLI needs neither the backend nor the dashboard, so it still works when the
platform is broken:

```bash
sudo bash scripts/bootstrap_upgrade.sh <tag>                  # online
sudo bash scripts/bootstrap_upgrade.sh --package <file|dir>   # air-gap apply
bash scripts/bootstrap_upgrade.sh <tag> --prepare /media/usb  # build a carry-in file
```

**Air-gap round trip** — `--prepare` on any online machine (no appliance needed)
writes one file carrying both the engine and the images; apply it offline.
Air-gap is supported from `intact-20260813` onward:

```bash
bash scripts/bootstrap_upgrade.sh intact-20260813 --prepare /media/usb
sudo bash scripts/bootstrap_upgrade.sh --package /media/usb/intact-upgrade-intact-20260813.tar
```

**Old box with no upgrade tooling** — a release before `intact-20260813` (e.g.
`intact-20260726`) has no `scripts/upgrade.sh` of its own. Pull the target
release's code into the `intact` folder first (this replaces `scripts/` and
`lib/` — the engine; your live `config.yaml` is skip-worktree, so it is left
alone), then run its upgrade. Every route above works from there:

```bash
cd /path/to/intact
git fetch
git checkout intact-20260813        # pull in the target release's engine
sudo bash scripts/upgrade.sh        # its own code upgrades this box to 20260813
```

**Which modules move** is automatic — only those whose version differs. Override
with `--only a,b`, `--skip a,b`, or `--reinstall a,b` (re-apply one already at
target, to repair a half-landed upgrade).

## Scripts

### Change Platform IP

Repoints an installed platform to a new IP — and doubles as the repair tool:
re-run it with the **current** IP to regenerate certs, configs and containers
when something is broken.

```bash
sudo bash scripts/change_ip.sh 192.168.120.11
```

> Velociraptor agents already on endpoints have the old IP baked in and will
> **not** reconnect. Redeploy them with the new installers in
> `client_installers/`, or keep the old IP reachable as an alias.

### Clean/Uninstall

To remove Intact.AI components (containers, volumes, data):

```bash
sudo bash scripts/clean.sh                 # interactive
sudo bash scripts/clean.sh --all --force   # full uninstall, no prompts
```

Scopes: `--all`, `--containers`, `--volumes`, `--images`, `--data`, `--logs`.
