# Risx Security Platform

A comprehensive security platform integrating Velociraptor EDR, ELK Stack, TimeSketch, IRIS, and custom management tools.

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

# 2. Extract the project (assuming risx.zip is already transferred to server)
unzip risx.zip

# 3. Enter directory
cd risx

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

To remove MSSP components (containers, volumes, data):

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

For distributing MSSP as a pre-configured VM image (OVA) to clients, including air-gapped environments.

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

---

## License

Internal use only.
