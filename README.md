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
# 1. Clone the release you want to install (see Releases for the latest tag)
git clone --branch intact-20260915 https://github.com/TenrootOrg/IntactAI.git intact

# Cloning without --branch gets `main`, which is for DEVELOPMENT. The installer
# still takes its images from a published release — the one main's VERSION file
# names — but the scripts, compose files and backend source come from your
# checkout. Mid-cycle those are newer than the release, so you get an installer
# and images from two different versions. Pin the tag and it installs as a unit.

cd intact

# 2. Edit configuration (set your IP/domain and passwords)
nano config.yaml

# 3. Run installer
sudo bash install.sh
```

### Air-gapped installation

> Supported from `intact-20260818` onward.

`--package` makes the installer take every image and dependency from the file
you carry in, never from a registry.

On a machine with internet:

```bash
# download and unpack the release into the project folder "intact"
# (to install a different release, replace intact-20260915 with its tag)
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20260915.tar.gz" -o intact-20260915.tar.gz
mkdir -p intact && tar -xzf intact-20260915.tar.gz --strip-components=1 -C intact
bash intact/scripts/prepare_package.sh intact-20260915 .   # writes intact-20260915-package.tar
tar -czf intact.tar.gz intact                               # one file to carry across
```

Carry **both** `intact.tar.gz` and `intact-20260915-package.tar` across —
two files, whatever the transfer medium (USB, DVD, ...). Then on the air-gapped
box:

```bash
tar -xzf intact.tar.gz
cd intact
nano config.yaml                                    # IP/domain and passwords
sudo bash install.sh --package ../intact-20260915-package.tar
```

`--package` is repeatable and also takes a directory of per-module assets. If
Docker is not already installed, carry the release's `intact-20260915-system-bundle.tar`
too and put it beside the package — it provides the engine and host packages
offline.

**Velociraptor tools.** An air-gapped install ships only the tools the default
blueprints use. Other artifacts' tools (Hayabusa, Sigcheck, Bulk Extractor, …)
are added with `scripts/velo_tools.sh` (`list` on the box → `fetch` where there
is internet → `import` back on the box) — see
[docs/VELOCIRAPTOR_TOOLS_AIRGAP.md](docs/VELOCIRAPTOR_TOOLS_AIRGAP.md).

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

An upgrade runs the **target release's own code** against your live `intact`
folder — download the release, then run its own `scripts/upgrade.sh` against
`--root ./intact`. It upgrades only the modules whose version differs, so you
can jump straight to any newer release in one hop. Every command below is
copy-paste; **to target a different release, replace `intact-20260915` with
its tag.** Pick the ONE section below that matches your box — each is
complete on its own, start to finish.

### Online (the box reaches GitHub)

Run this on the box itself:

```bash
cd ~
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20260915.tar.gz" -o intact-20260915.tar.gz
mkdir -p intact-20260915 && tar -xzf intact-20260915.tar.gz --strip-components=1 -C intact-20260915
cd ~ && sudo bash intact-20260915/scripts/upgrade.sh intact-20260915 --root ./intact
```

### Air-gapped

**Step 1 — on any machine WITH internet** (not the box):

```bash
cd ~
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20260915.tar.gz" -o intact-20260915.tar.gz
mkdir -p intact-20260915 && tar -xzf intact-20260915.tar.gz --strip-components=1 -C intact-20260915
# one file with the engine + every image (add module names for a subset,
# e.g. add  portainer  as a last argument)
bash intact-20260915/scripts/prepare_package.sh intact-20260915 .   # -> intact-20260915-package.tar
tar -czf intact-20260915-checkout.tar.gz intact-20260915            # the release folder, as one file
```

Carry **both** `intact-20260915-checkout.tar.gz` and `intact-20260915-package.tar`
to the box — two files, whatever the transfer medium (USB, DVD, ...).

**Step 2 — on the AIR-GAPPED box** (a different machine, a fresh shell):

```bash
cd ~
tar -xzf intact-20260915-checkout.tar.gz
cd ~ && sudo bash intact-20260915/scripts/upgrade.sh --package intact-20260915-package.tar --root ./intact
```

Or push-button in the dashboard: **Settings → Online Upgrade / Prepare Package /
Import Package** — the same engine, no shell.

### Upgrading only some modules

> ⚠️ **Not recommended. Be careful.** A release is tested as a whole, and this
> is the one way to end up running a combination nobody QA'd: a new backend
> against an older Timesketch, ELK or IRIS. Module upgrades sometimes depend on
> each other and the engine does not check for that — if it breaks, the fix is a
> full upgrade to the same tag. Use it when a full upgrade is impractical (a slow
> or metered link, a maintenance window too short for ~8 GB), not as the default.

`--only` limits both the **download** and the apply, so only the named modules
are fetched. Two examples:

```bash
cd ~/intact

# just the platform itself — backend, dashboard, engine (~460 MB)
sudo bash scripts/upgrade.sh intact-20260915 --only intact

# the platform plus Velociraptor (755 MB, measured)
sudo bash scripts/upgrade.sh intact-20260915 --only intact,velociraptor
```

Against ~7.8 GB for the whole release. The second one printed

```
  MODULE           INSTALLED            PACKAGE              ACTION
  intact           intact-20260903      intact-20260915      UPGRADE
  velociraptor     0.77.2               0.77.2               -
  elk              9.4.4                9.4.4                skip (excluded by --only)
  timesketch       20260630             20260630             skip (excluded by --only)
  ...
```

Notes:

- **`intact` is always fetched**, named or not — its asset carries the upgrade
  engine (`source/intact/scripts/upgrade.sh`) that the run hands over to. The log
  says so: `Fetching only: velociraptor intact`.
- **Module names** are `intact`, `elk`, `timesketch`, `plaso`, `iris`,
  `velociraptor`, `aws_sigma`, `o365rc`, `volweb`, `portainer`. Anything else is
  rejected with the list.
- **`--skip <csv>`** is the inverse — upgrade everything except these.
- **See it first, without root:** `bash scripts/upgrade.sh --plan intact-20260915
  --only intact,velociraptor` downloads only the ~0.2 MB manifest, prints the
  table above and changes nothing.
- **Air-gapped equivalent:** pass the modules to `prepare_package.sh` —
  ```bash
  bash intact-20260915/scripts/prepare_package.sh intact-20260915 . intact
  bash intact-20260915/scripts/prepare_package.sh intact-20260915 . intact,velociraptor
  ```
- The box still reports the **release tag** as its version afterwards, even
  though only some modules moved. `versions.txt` in a support bundle (and
  `versions.json`, from `intact-20260916` on) shows the per-module pins, which is
  where a partial upgrade is actually visible.

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
