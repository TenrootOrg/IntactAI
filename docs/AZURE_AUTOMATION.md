# Azure Security Automation

Azure/M365 security log collection and SIGMA-based detection with LLM analysis.

## Overview

This feature provides Azure security automation similar to the Velociraptor agentic pipeline:
- **Collection**: DFIR-O365RC (online) or manual upload (offline)
- **Detection**: SIGMA rules (50+ Azure/M365 rules from SigmaHQ)
- **Analysis**: LLM-powered analysis of findings
- **Reporting**: Executive and technical reports
- **Integration**: IRIS timeline import

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 AZURE AGENTIC PIPELINE                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MODE SELECT                                                    │
│     ├─→ ONLINE: API connection to Azure                        │
│     └─→ OFFLINE: Upload logs manually                          │
│                                                                  │
├─────────────────────────────────────────────────────────────────┤
│  ONLINE MODE                          │  OFFLINE MODE           │
│  ─────────────                        │  ────────────           │
│  1. Auth (Service Principal)          │  1. Upload JSON/CSV     │
│  2. License detection (Free/P1/P2)    │     (Unified Audit,     │
│  3. DFIR-O365RC collection            │      Sign-in logs,      │
│     └─→ Auto-adapt to tier            │      Activity logs)     │
│                                       │                         │
├───────────────────────────────────────┴─────────────────────────┤
│                                                                  │
│  SHARED PIPELINE (both modes)                                   │
│  ────────────────────────────                                   │
│  4. DETECTION (SIGMA Rules via pySigma)                        │
│     ├─→ 50+ Azure/Entra ID detection rules                     │
│     ├─→ Outputs only matching findings                         │
│     └─→ MITRE ATT&CK mapped                                    │
│                                                                  │
│  5. LLM ANALYSIS (Reuse analyzers.py)                          │
│     └─→ Analyze SIGMA findings                                 │
│                                                                  │
│  6. REPORT GENERATION (Reuse reports.py)                       │
│     └─→ Executive + Technical reports                          │
│                                                                  │
│  7. IRIS IMPORT (Reuse iris_service.py)                        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## License Tier Support

| Log Source | Free | P1 | P2 | SIGMA Rules |
|------------|------|-----|-----|-------------|
| Unified Audit Log | Yes | Yes | Yes | 20+ rules |
| Azure Activity | Yes | Yes | Yes | 10+ rules |
| Sign-in Logs | 7 days | 30 days | 30 days | 15+ rules |
| Risky Sign-ins | No | No | Yes | 5+ rules |
| Identity Protection | No | No | Yes | 5+ rules |

**Auto-detection**: The system tries each source and skips on 403 error, reporting what was collected.

## Blueprints

| Blueprint | Log Sources | Use Case |
|-----------|-------------|----------|
| **Quick Scan** | Unified Audit (7 days) | Fast check, works on Free tier |
| **Full Investigation** | All available (30 days) | Complete security picture |
| **Identity Focus** | Sign-in + Audit logs | Compromised account investigation |
| **Persistence Hunt** | Audit + Activity logs | Backdoor detection |

## API Endpoints

### Online Mode
- `POST /api/azure/scan` - Start live collection + detection

### Offline Mode
- `POST /api/azure/upload` - Upload logs (JSON/JSONL/CSV)
- `POST /api/azure/analyze-offline` - Run SIGMA + LLM on uploaded logs

### Shared
- `GET /api/azure/status` - Service status
- `GET /api/azure/status/{run_id}` - Run status
- `GET /api/azure/results/{run_id}` - Collected/uploaded data
- `GET /api/azure/findings/{run_id}` - SIGMA detection findings
- `GET /api/azure/analysis/{run_id}` - LLM analysis results
- `GET /api/azure/blueprints` - Available blueprints
- `GET /api/azure/sources` - Available log sources

## Configuration

### Azure Credentials (Settings Page)
- Tenant ID
- Client ID (App ID)
- Client Secret
- Subscription ID (optional)

### Required Azure AD Permissions
- `AuditLog.Read.All` - Sign-in and audit logs
- `IdentityRiskEvent.Read.All` - Risk detections (P2)
- `SecurityEvents.Read.All` - Security alerts
- `RoleManagement.Read.Directory` - PIM logs
- `Directory.Read.All` - Directory context

## Files

### Backend Services
- `services/azure/__init__.py` - Package exports
- `services/azure/collectors.py` - Online/offline collection
- `services/azure/sigma_runner.py` - SIGMA rule execution
- `services/azure/pipeline.py` - Pipeline orchestration

### Routes
- `routes/azure_routes.py` - API endpoints

### Configuration
- `config/default_blueprints.yaml` - Azure blueprints section

### Installation
- `install.sh` - Calls `download_sigma_rules`
- `lib/docker.sh` - `download_sigma_rules()` function

## Dependencies

Python packages (requirements.txt):
```
pysigma>=0.10.0
azure-identity>=1.15.0
msgraph-sdk>=1.0.0
```

External:
- SIGMA rules: `/opt/sigma-rules` (cloned from SigmaHQ)

## Usage

### Online Mode (Live Collection)
1. Configure Azure credentials in Settings
2. Go to Automation > Cloud > Azure
3. Select "Online Collection"
4. Choose blueprint and time filter
5. Click "Start Azure Scan"

### Offline Mode (Upload Logs)
1. Export logs from Azure/M365 (JSON, JSONL, or CSV)
2. Go to Automation > Cloud > Azure
3. Select "Offline Analysis"
4. Upload log files
5. Click "Analyze Uploaded Logs"

## SIGMA Detection Categories

| Category | Rules | Example Detections |
|----------|-------|-------------------|
| Authentication | 15+ | Brute force, password spray, impossible travel |
| Privilege Escalation | 10+ | New admin, role assignment, PIM abuse |
| Persistence | 8+ | Service principal creation, federation changes |
| Data Access | 5+ | Bulk downloads, sharing policy changes |
| Evasion | 5+ | Conditional access bypass, MFA manipulation |
