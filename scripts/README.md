# Scripts

## Available Scripts

### generate_clients.sh
Generates Velociraptor client installers. Called automatically by `install.sh`.

### repair_modules.sh
Checks and repairs failed MSSP modules.

```bash
# Check status of all modules
sudo bash scripts/repair_modules.sh

# Repair all failed modules automatically
sudo bash scripts/repair_modules.sh --repair-failed

# Repair a specific module
sudo bash scripts/repair_modules.sh <module_name>
```

Available modules: `elk`, `timesketch`, `velociraptor`, `iris`, `portainer`, `backend`, `nginx`

Generates log file: `repair_YYYYMMDD_HHMMSS.log`

### clean.sh
Removes MSSP components (containers, volumes, data). Use with caution!

```bash
# Interactive mode
sudo bash scripts/clean.sh

# Remove everything (full uninstall)
sudo bash scripts/clean.sh --all

# Remove containers only (keep data)
sudo bash scripts/clean.sh --containers

# Skip confirmation prompts
sudo bash scripts/clean.sh --all --force
```

Options: `--all`, `--containers`, `--volumes`, `--images`, `--data`, `--logs`, `--force`

---

See main README.md for installation instructions.
