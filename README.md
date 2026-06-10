# Intact.AI Security Platform

A comprehensive security platform integrating Velociraptor EDR, ELK Stack, TimeSketch, IRIS, and custom management tools.

<!-- readme propagation test 2026-04-29 -->

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
# e.g. --branch intact-20260609  (see the Releases tab for tags).

cd intact

# 2. Edit configuration (set your IP/domain and passwords)
nano config.yaml

# 3. Run installer
sudo bash install.sh
```

## Services

All services terminate TLS through the main nginx. Detailed port allocations (internal docker-network ports, agent comms, install/runtime egress) are in the [Network / Firewall Ports](#network--firewall-ports) section below.

| Service | Description | Access |
|---------|-------------|--------|
| **Dashboard** | Web UI — workflows, blueprints, reports, settings | `https://YOUR_IP` |
| **Velociraptor** | Endpoint forensics + remote collection (reverse-proxied — use `/velociraptor/`, not the upstream port directly) | `https://YOUR_IP/velociraptor/` |
| **TimeSketch** | Timeline analysis — ingest Plaso super-timelines and pivot across multi-host investigations from a single view | `https://YOUR_IP:5000` |
| **ELK Stack** | Searchable log store + visualization. Indexes Velociraptor artifact hunts and Sigma rule matches; Kibana is the analyst-facing dashboard. | `https://YOUR_IP:5601` (Kibana) |
| **IRIS** | Case management — track open incidents, assignees, evidence chains, and IR runbook progress across the engagement | `https://YOUR_IP:8443` |
| **VolWeb** | Memory forensics (Volatility 3 + YARA) | `https://YOUR_IP:8002` |
| **Portainer** | Container management — inspect, restart, and tail logs of the IntactAI service containers from a web UI | `https://YOUR_IP:9443` |

## Configuration

Edit `config.yaml` before installation:

```yaml
domain: 192.168.1.96  # Your server IP or domain

modules:
  elk:
    enabled: true
    id: elastic
    password: 'your-password'
  velociraptor:
    enabled: true
    id: admin
    password: 'your-password'
  timesketch:
    enabled: true
    id: admin
    password: 'your-password'
  iris:
    enabled: true
    id: administrator
    password: 'your-password'
  portainer:
    enabled: true
    id: admin
    password: 'your-password'

versions:
  elk: 9.2.3
  iris: v2.4.24
  portainer: 2.33.6
  timesketch: '20260209'
  velociraptor: '0.75'
```

## Network / Firewall Ports

Open these on the IntactAI server:

| Direction | Port | Purpose |
|-----------|------|---------|
| **Inbound — analyst access** | TCP 443 | Dashboard + `/velociraptor/` + `/api/` proxy. **The main one.** |
| | TCP 80 | HTTP → HTTPS redirect |
| | TCP 5000, 5601, 8002, 8443, 9443 | TimeSketch, Kibana, VolWeb, IRIS, Portainer (lock to analyst subnet) |
| **Inbound — Velociraptor agents** | TCP 8000 (TLS) | **Required.** Every endpoint phones home here. If blocked, agents silently never appear in the Clients list. |
| **Outbound — install** | TCP 443 | Docker Hub, GitHub, Ubuntu apt, PyPI (for image pulls + Velociraptor binaries + SIGMA / YARA rules). Skip if using the offline upgrade package. |
| **Outbound — runtime, per module** | TCP 443 | OpenRouter / Anthropic / Google (online LLM); `*.microsoftonline.com` + `graph.microsoft.com` (Azure scans); `*.amazonaws.com` (AWS scans); GitHub (YARA refresh). Only required if you enable that module. |

**Minimum-viable deployment:** open 443 inbound from analysts, 8000 inbound from endpoint subnets, 443 outbound during install. Everything else is opt-in per module.

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
the installer uses, then restarts the affected containers.

```bash
# Interactive (asks for confirmation)
sudo bash scripts/change_ip.sh 192.168.120.11

# Non-interactive
sudo bash scripts/change_ip.sh 192.168.120.11 --yes
```

What it does:
1. Sets `domain: <NEW_IP>` in `config.yaml`
2. Re-propagates the IP into `modules/velociraptor/.env`
3. Sweeps `modules/` + `scripts/` for any stray old-IP literals and replaces them
4. Regenerates the TLS certificates with `CN=<NEW_IP>` (nginx + IRIS)
5. Patches the Velociraptor server config, restarts it so the client
   config + API config regenerate, and restarts the backend
6. Refreshes the nginx containers (clears upstream DNS cache + serves the new cert)
7. Regenerates the Velociraptor client installers in `client_installers/`

It is idempotent (re-running with the current IP is a no-op) and safe to
re-run if interrupted.

> **Note:** Velociraptor agents already deployed on endpoints have the
> old server IP baked in and will **not** reconnect. Redeploy those
> endpoints with the freshly generated installers in `client_installers/`,
> or keep the old IP reachable as an alias. Browser TLS warnings are
> expected (self-signed certificate).

### Clean/Uninstall

To remove Intact.AI components (containers, volumes, data):

```bash
# Interactive mode - choose what to remove
sudo bash scripts/clean.sh

# Remove everything (full uninstall)
sudo bash scripts/clean.sh --all

# Remove containers only (keep data)
sudo bash scripts/clean.sh --containers

# Remove without confirmation prompts
sudo bash scripts/clean.sh --all --force
```

Available options:
- `--all` - Remove everything (containers, volumes, data, configs)
- `--containers` - Remove containers only (keep volumes and data)
- `--volumes` - Remove Docker volumes only
- `--images` - Remove Docker images only
- `--data` - Remove data directory only
- `--logs` - Remove log files only

---

## VM Image Distribution

For distributing Intact.AI as a pre-configured VM image (OVA) to clients, including air-gapped environments.

### Client First Boot

After client imports the VM and edits `config.yaml`:

```bash
# Initialize all services
sudo bash install.sh
```

**What it does:**
1. Syncs domain from `config.yaml` to all services
2. Generates SSL certificates (Nginx, IRIS)
3. Creates IRIS secrets from `config.yaml` passwords
4. Starts all Docker services in order
5. Generates Velociraptor client installers (air-gap safe)

### Distribution Workflow

1. **Export:** Create OVA/snapshot in your hypervisor
2. **Deliver:** Transfer OVA to client (network or USB)
3. **Client Setup:**
   - Import OVA
   - Edit `config.yaml` (set IP/domain and passwords)
   - Run `sudo bash install.sh`
   - Access dashboard at `http://CLIENT_IP`

## Agentic skill audits

The DFIR skills bundled with the agentic pipeline are audited on every
update. Latest results:

- 🔒 **Security scan** ([`cisco_scan.csv`](modules/backend/services/agentic/skills/audits/cisco_scan.csv))
  — scanned with [Cisco AI Defense Skill Scanner](https://github.com/cisco-ai-defense/skill-scanner).
  **0 malicious · 6 false_positive · 63 safe** (69 total).
- 📈 **Value evaluation** ([`value_evaluation.csv`](modules/backend/services/agentic/skills/audits/value_evaluation.csv))
  — each skill runs through a baseline-vs-skilled LLM-as-judge comparison.
  **38 high_value · 30 moderate_value · 1 low_value · 0 worse**.

Methodology + per-skill detail: [`modules/backend/services/agentic/skills/README.md`](modules/backend/services/agentic/skills/README.md).

## Third-party data

The CVE Scan module (Automation → On-Prem → CVE Scan) uses two
locally-cached, upstream-refreshable feeds so scans are fast and
work fully offline once populated:

1. **CPE vendor:product dictionary** — at
   [`modules/backend/services/cve_scan/data/cpes.csv`](modules/backend/services/cve_scan/data/cpes.csv).
   Resolves installed-software names to CPE identifiers. Vendored
   from [**tiiuae/cpedict**](https://github.com/tiiuae/cpedict)
   (daily-rebuilt from NVD's official
   [CPE Dictionary](https://nvd.nist.gov/products/cpe)).
2. **Local CVE mirror** — a SQLite index at
   `/app/data/cve_cache/cves.db` covering NVD's full CVE corpus
   (~350,000 entries). Populated from the community-maintained
   [**fkie-cad/nvd-json-data-feeds**](https://github.com/fkie-cad/nvd-json-data-feeds)
   project, which reconstructs the per-year compressed JSON files
   NIST retired in Dec 2023 and refreshes them every 2 hours.
   Replaces per-product NVD REST calls — a 1,000-product scan that
   used to take 10-30 minutes now finishes in seconds.

Both refresh paths:
- **Fresh install**: the backend bootstraps both on first start
  (`init_db()` is cheap; the ~50 MB CVE-feed download runs in a
  background thread so the API serves immediately and scans
  transparently fall back to NVD REST until the bulk load finishes).
- **Manual refresh**: Settings → Maintenance → Task 3.5 refreshes
  both in place without a restart.

Live CVE metadata at scan time still comes from the
[NVD REST API 2.0](https://nvd.nist.gov/developers/vulnerabilities)
as a fallback when the local DB hasn't seen a product yet, with an
optional operator-supplied API key (Settings → CVE Scan) for the
50 req/30 s rate tier.

### Attribution & terms

The downstream data we redistribute (the cached CVE records, CPE
bindings, CVSS scores) is sourced from MITRE's CVE List and NIST's
National Vulnerability Database. Both are public-domain U.S.
Government records governed by their own terms of use:

- **CVE records** — © MITRE Corporation, under the
  [CVE Terms of Use](https://www.cve.org/Legal/TermsOfUse). Public
  data; redistribution requires the "as-is, no warranties" notice.
- **NVD enrichment** (CPE, CVSS, descriptions) — © NIST, under the
  [NVD Terms of Use](https://nvd.nist.gov/developers/terms-of-use).
  Public data; users must acknowledge NVD as the source.
- **fkie-cad/nvd-json-data-feeds** (community redistribution
  pipeline) — the upstream project does not state a separate
  license; it explicitly notes "uses and redistributes data from
  the NVD API but is neither endorsed nor certified by the NVD."
  We rely on the same disclaimer for our local cache.
- **tiiuae/cpedict** — same pattern; redistributes NVD CPE entries
  under NVD's TOU.

Intact does not modify the CVE descriptions, IDs, or CVSS scores
during scanning; it only matches installed products against them.
