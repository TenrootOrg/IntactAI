# Scripts

## Available Scripts

### generate_clients.sh
Generates Velociraptor client installers. Called automatically by `install.sh`.

### clean.sh
Removes Intact.AI components (containers, volumes, data). Use with caution!

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
