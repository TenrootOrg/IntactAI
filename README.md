# Intact.AI Security Platform

A comprehensive security platform integrating Velociraptor EDR, ELK Stack, TimeSketch, IRIS, and custom management tools.

## License & Attribution

| Component | License |
|---|---|
| **Intact.AI** — see [LICENSE](./LICENSE) | **AGPL-3.0** |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | AGPL-3.0 |
| [Timesketch](https://github.com/google/timesketch) | Apache-2.0 |
| [Plaso](https://github.com/log2timeline/plaso) | Apache-2.0 |
| [Presidio](https://github.com/microsoft/presidio) | MIT |
| [spaCy](https://github.com/explosion/spaCy) and its `en_core_web_lg` model | MIT |
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
git clone --branch intact-20261008 https://github.com/TenrootOrg/IntactAI.git intact

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
# (to install a different release, replace intact-20261008 with its tag)
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20261008.tar.gz" -o intact-20261008.tar.gz
mkdir -p intact && tar -xzf intact-20261008.tar.gz --strip-components=1 -C intact
bash intact/scripts/prepare_package.sh intact-20261008 .   # writes intact-20261008-package.tar
tar -czf intact.tar.gz intact                               # one file to carry across
```

Carry **both** `intact.tar.gz` and `intact-20261008-package.tar` across —
two files, whatever the transfer medium (USB, DVD, ...). Then on the air-gapped
box:

```bash
tar -xzf intact.tar.gz
cd intact
nano config.yaml                                    # IP/domain and passwords
sudo bash install.sh --package ../intact-20261008-package.tar
```

`--package` is repeatable and also takes a directory of per-module assets. If
Docker is not already installed, carry the release's `intact-20261008-system-bundle.tar`
too and put it beside the package — it provides the engine and host packages
offline.

**Velociraptor tools.** An air-gapped install ships only the tools the default
blueprints use. Other artifacts' tools (Hayabusa, Sigcheck, Bulk Extractor, …)
are added with `scripts/velo_tools.sh` (`list` on the box → `fetch` where there
is internet → `import` back on the box) — see
[docs/VELOCIRAPTOR_TOOLS_AIRGAP.md](docs/VELOCIRAPTOR_TOOLS_AIRGAP.md).

## Services & Ports

Every web UI sits behind the main nginx, which terminates TLS and asks for
the Intact login before proxying. Access is `https://YOUR_IP` unless a port is
listed. The modules' own ports (5000, 5601, 8443, 9200, 9443) are bound to
`127.0.0.1` for on-box use only. `install.sh` starts containers only for
enabled modules.

| Module | What it does | Access | Containers |
|---|---|---|---|
| **Dashboard** | Web UI — workflows, blueprints, reports, settings | `/` | `intact_backend`, `intact_tusd`, `intact_nginx` |
| **Velociraptor** | Endpoint forensics + remote collection | `/velociraptor/` (proxied — not the upstream port) | `intact_velociraptor` |
| **TimeSketch** | Timeline analysis — ingests Plaso super-timelines, pivots across hosts from one view | `:5443` | `intact_timesketch_web`, `_web_v3`, `_web_legacy`, `_worker`, `_nginx`, `_postgres`, `_redis`, `_opensearch` |
| **ELK** | Searchable log store + Kibana. Indexes Velociraptor hunts and Sigma matches | `:5602` (Elasticsearch is box-only) | `intact_elasticsearch`, `intact_logstash`, `intact_kibana` |
| **IRIS** | Case management — incidents, assignees, evidence chains, runbook progress | `:8444` | `intact_iris_app`, `_db`, `_worker`, `_rabbitmq`, `_nginx` |
| **VolWeb** | Memory forensics (Volatility 3 + YARA) | `:8002` | `intact_volweb_frontend`, `_backend`, `_workers`, `_workers_yarascan`, `_postgresdb`, `_redis` |
| **Portainer** | Container management — inspect, restart, tail logs | `:9444` | `intact_portainer`, `intact_portainer_agent` |
| **Case Analysis (Fusion)** | Correlates every host + module into one incident graph → fused report, advisory, timeline, Identities, and grounded chat | in Dashboard | — |
| **Memory** | Remote acquisition (AVML / WinPmem), analysed in the VolWeb stack | in Dashboard | — |
| **Cloud DFIR** | AWS **CloudTrail** and Microsoft 365 / Azure AD **(DFIR-O365RC)** collection + SIGMA detections | in Dashboard | in `intact_backend` |
| **Plaso** | Super-timeline generation | via TimeSketch | image pulled per job |
| **Presidio** | Second masking pass: hides person and company names the pattern masker misses before case data reaches an AI model. Always installed; works air-gapped | Case Analysis → Mask → Presidio | `intact_presidio`, started per report, stops when idle |
| **Scheduler / Blueprints / Agentic** | Scheduled collections, reusable blueprints, agentic quick-wins | in Dashboard | — |

> The search engines — TimeSketch's OpenSearch and ELK's Elasticsearch/Kibana —
> are the biggest RAM/CPU consumers. On a small host, `docker stop` the stacks
> you are not using.


**Firewall.** `443` in from analysts (Dashboard, `/velociraptor/`, `/api/`) and
`8000` in from endpoint subnets — Velociraptor agents phone home on 8000, and if
it is blocked they silently never appear in the Clients list. `80` redirects to
HTTPS. The nginx module ports above (5602, 9444, 8444, 5443, 8002) should be
locked to the analyst subnet.

**Changing a port.** Each tool's public port lives under its module in
`config.yaml`; a missing key means the default:

| Tool | `config.yaml` key | Default |
|---|---|---|
| Kibana | `modules.elk.kibana_port` | `5602` |
| Portainer | `modules.portainer.port` | `9444` |
| IRIS | `modules.iris.port` | `8444` |
| TimeSketch | `modules.timesketch.port` | `5443` |
| VolWeb | `modules.volweb.port` | `8002` |
| Velociraptor agents | `modules.velociraptor.agent_port` | `8000` |

To change one on an installed box, see
[Changing the IP or ports after install](#changing-the-ip-or-ports-after-install).
The dashboard stays on `443`, and the box-only module ports are fixed. An
upgrade keeps the ports the box already uses.

`443` outbound is used during install and upgrade, and by enabled modules that
call out (LLM providers, Microsoft Graph, AWS). It can be skipped entirely if
you install and upgrade from packages.

## Upgrades

An upgrade runs the **target release's own code** against your live `intact`
folder — download the release, then run its own `scripts/upgrade.sh` against
`--root ./intact`. It upgrades only the modules whose version differs, so you
can jump straight to any newer release in one hop. Every command below is
copy-paste; **to target a different release, replace `intact-20261008` with
its tag.** Pick the ONE section below that matches your box — each is
complete on its own, start to finish.

### Online (the box reaches GitHub)

Run this on the box itself:

```bash
cd ~
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20261008.tar.gz" -o intact-20261008.tar.gz
mkdir -p intact-20261008 && tar -xzf intact-20261008.tar.gz --strip-components=1 -C intact-20261008
cd ~ && sudo bash intact-20261008/scripts/upgrade.sh intact-20261008 --root ./intact
```

### Air-gapped

**Step 1 — on any machine WITH internet** (not the box):

```bash
cd ~
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20261008.tar.gz" -o intact-20261008.tar.gz
mkdir -p intact-20261008 && tar -xzf intact-20261008.tar.gz --strip-components=1 -C intact-20261008
# one file with the engine + every image (add module names for a subset,
# e.g. add  portainer  as a last argument)
bash intact-20261008/scripts/prepare_package.sh intact-20261008 .   # -> intact-20261008-package.tar
tar -czf intact-20261008-checkout.tar.gz intact-20261008            # the release folder, as one file
```

Carry **both** `intact-20261008-checkout.tar.gz` and `intact-20261008-package.tar`
to the box — two files, whatever the transfer medium (USB, DVD, ...).

**Step 2 — on the AIR-GAPPED box** (a different machine, a fresh shell):

```bash
cd ~
tar -xzf intact-20261008-checkout.tar.gz
cd ~ && sudo bash intact-20261008/scripts/upgrade.sh --package intact-20261008-package.tar --root ./intact
```

Or push-button in the dashboard: **Settings → Online Upgrade / Prepare Package /
Import Package** — the same engine, no shell.

### Upgrading only some modules

> ⚠️ **Not recommended — be careful.** A release is tested as a whole, and this
> is the one way to end up running a combination nobody QA'd: a new backend
> against an older Timesketch, ELK or IRIS. The engine does not check whether one
> module's upgrade needed another's. If it breaks, the fix is a full upgrade to
> the same tag.

`--only <csv>` limits both the **download** and the apply, so only the named
modules are fetched.

**Internet:**

```bash
cd ~/intact

# just the platform itself — backend, dashboard, engine (~460 MB)
# sudo bash scripts/upgrade.sh intact-20261008 --only intact

# the platform plus Velociraptor (755 MB, measured)
sudo bash scripts/upgrade.sh intact-20261008 --only intact,velociraptor
```

**Air-gapped** — the same flow as above, with the modules named as the third
argument to `prepare_package.sh`.

**Step 1 — on any machine WITH internet** (not the box):

```bash
cd ~
curl -fL "https://github.com/TenrootOrg/IntactAI/archive/refs/tags/intact-20261008.tar.gz" -o intact-20261008.tar.gz
mkdir -p intact-20261008 && tar -xzf intact-20261008.tar.gz --strip-components=1 -C intact-20261008

# just the platform itself
# bash intact-20261008/scripts/prepare_package.sh intact-20261008 . intact

# the platform plus Velociraptor
bash intact-20261008/scripts/prepare_package.sh intact-20261008 . intact,velociraptor

tar -czf intact-20261008-checkout.tar.gz intact-20261008   # the release folder, as one file
```

Carry **both** `intact-20261008-checkout.tar.gz` and `intact-20261008-package.tar`
to the box.

**Step 2 — on the AIR-GAPPED box:**

```bash
cd ~
tar -xzf intact-20261008-checkout.tar.gz
cd ~ && sudo bash intact-20261008/scripts/upgrade.sh --package intact-20261008-package.tar --root ./intact
```

Notes:

- **`intact` is always included**, named or not — its asset carries the upgrade
  engine (`source/intact/scripts/upgrade.sh`) that the run hands over to. The log
  says so: `Fetching only: velociraptor intact`.
- **Module names** are `intact`, `presidio`, `elk`, `timesketch`, `plaso`, `iris`,
  `velociraptor`, `aws_sigma`, `o365rc`, `volweb`, `portainer`. Anything else is
  rejected with the list.
- **`--skip <csv>`** is the inverse — upgrade everything except these.
- **Afterwards the box calls itself `intact-20261008`** even though only some
  modules moved — `VERSION` is stamped from the tag you upgraded to, not from
  what actually changed. So a box that took `--only intact` reports the same
  version as one that took the whole release, while its Timesketch, ELK and IRIS
  are still on the previous release's pins. The per-module pins are the real
  answer, and they are in `versions.txt` (and `versions.json`) inside a support
  bundle. Worth knowing before you debug one of these against the wrong baseline.

## Scripts

### Changing the IP or ports after install

One run applies whatever changed: the IP, the ports (the
[`config.yaml` keys above](#services--ports)), or both. If nothing changed it
says so and leaves the containers alone. Intact restarts its services and is
offline for a few minutes.

**From Settings.** Settings → General → **Network** → **Change IP / ports**.
Enter the new IP and ports and press Save. Intact writes them into
`config.yaml` and runs `scripts/change_ip.sh` on the host. The run and its
log are in **Settings → Actions**. If the IP changed, open Intact at
`https://NEW_IP/` once it is back.

**From a shell.** Edit the port keys in `config.yaml` if you are changing
ports, then from the `intact` folder:

```bash
sudo bash scripts/change_ip.sh 192.168.120.11   # new IP (and any port changes)
sudo bash scripts/change_ip.sh                  # ports only: keeps the IP in config.yaml
```

Add `-y` to skip the prompt. An invalid port in `config.yaml` stops the run
before it changes anything. The script also repairs a broken box: run it with
the **current** IP to regenerate certs, configs and containers.

> **Velociraptor agents.** Agents already on endpoints have the old IP and
> `agent_port` baked into their config, and they will **not** reconnect after
> either one changes. Redeploy them with the new installers in
> `client_installers/`, or keep the old IP reachable as an alias. Changing
> `agent_port` edits only the agent URL lines of Velociraptor's
> `server.config.yaml` and keeps a backup. The CA is not touched.

### Clean/Uninstall

To remove Intact.AI components (containers, volumes, data):

```bash
sudo bash scripts/clean.sh                 # interactive
sudo bash scripts/clean.sh --all --force   # full uninstall, no prompts
```

Scopes: `--all`, `--containers`, `--volumes`, `--images`, `--data`, `--logs`.
