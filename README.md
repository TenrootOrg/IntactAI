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
| **Dashboard** | Web interface | 80 |
| **Velociraptor** | EDR/Forensics | 8000 (GUI), 8001 (Frontend) |
| **ELK Stack** | Log Analytics | 9200 (ES), 5601 (Kibana) |
| **TimeSketch** | Timeline Analysis | 5000 |
| **IRIS** | Incident Response | 443 |
| **Backend API** | Management API | 5001 |
| **Portainer** | Container Management | 9443 |

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

After installation:

| Service | URL |
|---------|-----|
| Dashboard | `http://YOUR_IP` |
| Velociraptor | `http://YOUR_IP/velociraptor/` |
| TimeSketch | `http://YOUR_IP:5000` |
| Kibana | `http://YOUR_IP:5601` |
| IRIS | `https://YOUR_IP:443` |
| Portainer | `https://YOUR_IP:9443` |

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

### Prepare Image for Export

Before exporting the VM, clean all development artifacts:

```bash
# Preview what will be deleted (dry-run)
sudo bash scripts/prepare-image.sh --dry-run

# Clean everything for distribution
sudo bash scripts/prepare-image.sh

# Keep Claude Code files (for debugging)
sudo bash scripts/prepare-image.sh --keep-claude

# Keep .git and .ssh (for pushing fixes before final export)
sudo bash scripts/prepare-image.sh --keep-git
```

**What gets cleaned:**
- Docker containers and volumes (client/case data)
- SQLite databases and reports
- SSL certificates (regenerated on first-init)
- Client installers (regenerated on first-init)
- Log files, caches, history
- SSH keys, Claude Code files, VSCode server

**What stays:**
- `config.yaml` (client edits this)
- `data/tools/` (forensic tools for air-gapped)
- All source code

### Client First Boot

After client imports the VM and edits `config.yaml`:

```bash
# Initialize all services
sudo bash scripts/first-init.sh
```

**What it does:**
1. Syncs domain from `config.yaml` to all services
2. Generates SSL certificates (Nginx, IRIS)
3. Creates IRIS secrets from `config.yaml` passwords
4. Starts all Docker services in order
5. Generates Velociraptor client installers (air-gap safe)

### Distribution Workflow

1. **Prepare:** `sudo bash scripts/prepare-image.sh`
2. **Export:** Create OVA/snapshot in your hypervisor
3. **Deliver:** Transfer OVA to client (network or USB)
4. **Client Setup:**
   - Import OVA
   - Edit `config.yaml` (set IP/domain and passwords)
   - Run `sudo bash scripts/first-init.sh`
   - Access dashboard at `http://CLIENT_IP`
