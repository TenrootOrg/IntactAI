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
# 1. Install unzip
sudo apt update && sudo apt install -y unzip

# 2. Get the main branch ZIP from GitHub.
#    The repo is PRIVATE. Two options:
#
#    (a) Download manually in your browser (recommended for most users):
#        https://github.com/TenrootOrg/IntactAI  →  Code  →  Download ZIP
#        Transfer IntactAI-main.zip to the server.
#
#    (b) Or curl with a GitHub Personal Access Token (PAT) that has
#        repo-read access:
#        curl -L -H "Authorization: token <YOUR_GITHUB_PAT>" \
#          -o IntactAI-main.zip \
#          https://github.com/TenrootOrg/IntactAI/archive/refs/heads/main.zip

# 3. Extract and rename to "intact"
unzip IntactAI-main.zip
mv IntactAI-main intact
cd intact

# 4. Edit configuration (set your IP/domain and passwords)
nano config.yaml

# 5. Run installer
sudo bash install.sh
```

## Components

| Service | Description | Port |
|---------|-------------|------|
| **Dashboard** | Web UI (workflows, blueprints, reports) | 80, 443 |
| **Velociraptor** | DFIR / endpoint forensics | 8889 (GUI), 8000 (clients), 8001 (gRPC API) |
| **ELK Stack** | Log analytics (Elasticsearch + Kibana) | 9200 (ES), 5601 (Kibana) |
| **TimeSketch** | Timeline analysis | 5000 |
| **IRIS** | Incident response & case management | 8443 |
| **VolWeb** | Memory forensics (Volatility 3 + YARA) | 8002 |
| **Backend API** | Management API | 5001 |
| **Portainer** | Container management | 9443 |

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

## Accessing Services

After installation (all services terminate TLS through the main nginx):

| Service | URL | Notes |
|---------|-----|-------|
| Dashboard | `https://YOUR_IP` | |
| Velociraptor | `https://YOUR_IP/velociraptor/` | Reverse-proxied through main nginx. Direct access to Velociraptor's own GUI port (8889) is intentionally not exposed — a past header-handling bug caused redirect loops, the proxy path is the supported entry point. |
| TimeSketch | `https://YOUR_IP:5000` | |
| Kibana | `https://YOUR_IP:5601` | |
| IRIS | `https://YOUR_IP:8443` | |
| VolWeb | `https://YOUR_IP:8002` | |
| Portainer | `https://YOUR_IP:9443` | |

## Network / Firewall Ports

The IntactAI server needs the ports below open for the platform to work end-to-end. Listed by direction so a customer's network team can build the firewall rules without reverse-engineering the install.

### Inbound — operator / analyst access to the dashboard

These are the ports your SOC analysts hit from their workstations:

| Port | Protocol | Purpose |
|------|----------|---------|
| 80 | TCP | HTTP → HTTPS redirect (the dashboard itself is on 443) |
| 443 | TCP | Dashboard + `/velociraptor/` reverse proxy + `/api/` backend proxy. **The one port that matters most.** |
| 5000 | TCP | TimeSketch web UI (HTTPS) |
| 5601 | TCP | Kibana web UI (HTTPS) |
| 8002 | TCP | VolWeb memory-forensics UI (HTTPS) |
| 8443 | TCP | IRIS case-management UI (HTTPS) |
| 9443 | TCP | Portainer container-management UI (HTTPS) |

You can lock 5000 / 5601 / 8002 / 8443 / 9443 down to your analyst subnet if you don't expose them externally. 443 is the only one that has to be widely reachable from analyst desktops.

### Inbound — Velociraptor agents calling home

Every endpoint you deploy the Velociraptor agent to needs to reach the server on these ports. **This is the path that's easy to forget and breaks silently** — the dashboard looks fine, but no agents check in.

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | TCP (TLS) | **Required.** Velociraptor client → server frontend. Every Windows / Linux / macOS endpoint connects out to this port over TLS. Survives NAT — agents poll, server doesn't dial back. |
| 8001 | TCP | gRPC API. Used by the IntactAI backend and CLI tools. Keep on the server's local network only — does **not** need to be reachable from agents. |

If 8000 is blocked at the endpoint's perimeter (corporate firewall, host-based firewall, EDR rules), the agent shows up in the installer log but never appears in the dashboard's Clients list.

### Outbound — server reaching the internet

The IntactAI server needs to reach the internet on TCP/443 for these. If you run in an air-gapped environment, build an offline package with `Settings → Prepare Upgrade Package` from an online box and use `Settings → Import Package` on the air-gapped one.

**Install-time only:**

| Endpoint | Purpose |
|----------|---------|
| `download.docker.com` | Docker engine + GPG key |
| `registry-1.docker.io`, `production.cloudflare.docker.com` | Pulling container images (ELK, IRIS, Velociraptor, VolWeb, Postgres, etc.) |
| `github.com`, `raw.githubusercontent.com`, `codeload.github.com` | Cloning SIGMA rules, YARA rulesets (Neo23x0, Elastic, YARA-Forge), Velociraptor binaries, plugin artifacts |
| `archive.ubuntu.com`, `security.ubuntu.com` | apt packages |
| `pypi.org`, `files.pythonhosted.org` | Backend Python dependencies during image build |
| `nvd.nist.gov` (optional) | First CVE feed sync if you enable the CVE module |

**Runtime — only the ones you opt into:**

| Endpoint | Purpose | Required by |
|----------|---------|-------------|
| `openrouter.ai` (or `api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`) | LLM analysis for Agentic / AWS / Azure / Memory engagement reports | Agentic module when `llm_mode: online` |
| `login.microsoftonline.com`, `graph.microsoft.com`, `outlook.office365.com` | OAuth + Microsoft Graph + Office 365 audit log pulls | Azure scan module |
| `*.amazonaws.com` (region-specific) | AWS API for Prowler posture scans + custom collectors | AWS scan module |
| `github.com` | YARA ruleset refresh (Maintenance → Refresh YARA Rules) | VolWeb / Memory module |

### Internal — between containers on the IntactAI server

These are not firewall rules — they're just the docker-network ports the services use to talk to each other. Listed here so you know what the `docker ps` and `docker network inspect intact_network` output should look like:

| Container | Internal port | Talks to |
|-----------|---------------|----------|
| `intact_backend` | 5001 | Nginx, Velociraptor gRPC (8001), IRIS API, VolWeb API (8000), TimeSketch API, ELK (9200) |
| `intact_velociraptor` | 8000 / 8001 / 8889 | Agents (8000), backend (8001), proxied GUI (8889) |
| `intact_volweb_backend` | 8000 | Backend, frontend |
| `intact_iris_app` | 8000 (HTTPS via iris-web on 8443) | Backend |
| `intact_elasticsearch` | 9200 | Backend, Kibana |
| `intact_timesketch_web` | 5000 | Backend, nginx |
| `intact_timesketch_opensearch` | 9200 | timesketch_web |

### Quick "minimum viable" firewall summary

If you want to deploy in a tightly-restricted environment and are willing to use only the agent-collection + on-prem analysis flow (no cloud scans, no online LLM), open only:

- **Inbound:** TCP 443 from analyst subnet · TCP 8000 from endpoint subnets
- **Outbound at install:** TCP 443 to docker / github / ubuntu / pypi (use the offline package if you can't)
- **Outbound at runtime:** none required

Everything else is feature-specific and can be opened as you turn each module on.

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
