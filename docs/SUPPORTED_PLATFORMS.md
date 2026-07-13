# Supported Platforms (Host Layer)

IntactAI ships as a set of Docker containers. The **host layer** — the OS and
the Docker Engine underneath those containers — is **owned by the operator**,
not upgraded by the product. Restarting the Docker daemon from inside the
platform would kill every container mid-operation (including the upgrader
itself), so IntactAI never touches Docker or the OS automatically. Instead it
**preflights** the host and warns with remediation when something is below the
supported matrix, so problems surface as clear early messages instead of
cryptic failures later.

These checks are **advisory (warn-only)** — they never block install or
upgrade. The functional checks (Docker daemon reachable, Docker Compose v2
present) are what actually gate the flow.

## Supported matrix

| Component | Minimum (floor) | Recommended | Notes |
|-----------|-----------------|-------------|-------|
| **Ubuntu** | 20.04 LTS | 22.04 / 24.04 LTS | Tested on LTS releases only. Other distros usually work but are untested. |
| **Docker Engine** | 20.10 | 24.0+ | 20.10 is the Compose-v2-plugin era. IntactAI drives everything through `docker compose` (v2). |
| **Docker Compose** | v2 (plugin) | v2 latest | The legacy `docker-compose` v1 binary is **not** supported. |

The version constants live in two places and must stay in sync with this table:

- Shell (install): `lib/common.sh` → `INTACT_MIN_DOCKER_VERSION`,
  `INTACT_REC_DOCKER_VERSION`, `INTACT_SUPPORTED_UBUNTU`.
- Python (upgrade preflight): `modules/backend/services/upgrade/config_validate.py`
  → `MIN_DOCKER_VERSION`, `REC_DOCKER_VERSION`.

All three can be overridden via environment variables of the same name for the
shell checks (e.g. in CI).

## Where the checks run

| Surface | Check | Location |
|---------|-------|----------|
| `install.sh` (online) | Ubuntu version, Docker floor/recommended | `check_ubuntu` (`lib/docker.sh`), `check_docker_min_version` (`lib/common.sh`), called from `install.sh` |
| Online / offline upgrade | Docker floor/recommended (+ existing daemon & compose-v2 gates) | `preflight_environment` (`config_validate.py`) |

## Patching the host

Keep the host patched through your own patch-management process
(`unattended-upgrades`, your configuration-management tool, etc.):

```bash
# Docker Engine (Ubuntu) — operator-run, in a maintenance window:
sudo apt-get update && sudo apt-get install --only-upgrade docker-ce docker-ce-cli containerd.io docker-compose-plugin
```

Upgrading Docker restarts the daemon and therefore all IntactAI containers — do
it deliberately, not during an IntactAI install or upgrade.
