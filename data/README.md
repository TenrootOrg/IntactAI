# Data Directory

This directory contains the SQLite database for the MSSP platform.

## Contents

- `mssp.db` - SQLite database (workflows, blueprints, offline collectors, reports, frontend config)

## Storage Model

The MSSP platform uses **SQLite** for all persistent data. This provides:

- **Persistence**: Data survives container restarts and rebuilds
- **Concurrency**: WAL mode for safe concurrent reads/writes
- **Simplicity**: Single file, no external database dependencies
- **Portability**: Easy to backup, restore, and migrate
- **Export/Import**: API endpoints for JSON export/import

## Elasticsearch Usage

Elasticsearch is still used for:
- ELK Stack (Kibana log analytics)
- TimeSketch (timeline analysis)

But NOT for:
- Workflow storage
- Blueprint configurations
- Offline collector configurations
- Reports
- Frontend settings

## Initialization

On first startup, the backend automatically:
1. Creates `mssp.db` with all required tables
2. Migrates any existing JSON files (from previous versions)
3. Seeds default blueprints and offline collector templates

## Backup

To backup your database:
```bash
cp data/mssp.db data/mssp.db.backup
```

To restore:
```bash
cp data/mssp.db.backup data/mssp.db
```

Or use the API:
```bash
# Export as JSON
curl http://localhost:5001/api/db/export > backup.json

# Import from JSON
curl -X POST -H "Content-Type: application/json" -d @backup.json http://localhost:5001/api/db/import

# Download raw .db file
curl http://localhost:5001/api/db/backup > mssp.db
```
