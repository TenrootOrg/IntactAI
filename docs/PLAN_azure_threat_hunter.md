# Azure Agentic Pipeline Design (Threat Hunting & IR)

## Context
Create an agentic pipeline for Azure focused on **incident response and threat hunting** - detecting active threats, compromises, and suspicious activity. Similar to how DetectRaptor finds malicious behavior on endpoints, this detects malicious behavior in Azure/M365 environments.

**NOT compliance scanning** - we want to detect actual attacks, not misconfigurations.

## Approach: Direct Graph API (Python)

Instead of PowerShell tools (Sparrow/Hawk) that require Windows dependencies, we implement the **same detection logic** using Microsoft Graph API directly in Python. This runs natively on Ubuntu.

### Detection Modules

| Module | Graph API Endpoints | What It Detects |
|--------|---------------------|-----------------|
| **Sign-In Analysis** | `/auditLogs/signIns` | TOR/VPN logins, impossible travel, risky IPs, failed attempts |
| **OAuth/App Abuse** | `/servicePrincipals`, `/oauth2PermissionGrants` | Malicious apps, excessive permissions, suspicious consent |
| **Inbox Rules** | `/users/{id}/mailFolders/inbox/messageRules` | Auto-forward to external, auto-delete (hiding tracks) |
| **Admin Actions** | `/auditLogs/directoryAudits` | Role assignments, password resets, MFA changes |
| **Mail Forwarding** | `/users/{id}/mailboxSettings` | SMTP forwarding to external addresses |

### Risk Indicators (What We Flag)

**Sign-In Risks:**
- Login from TOR exit node or known VPN
- Impossible travel (US → Russia in 1 hour)
- Multiple failed logins then success
- Login from country user never visited
- Legacy auth protocols (often bypasses MFA)

**OAuth/App Risks:**
- App with Mail.ReadWrite, Files.ReadWrite.All
- App created at unusual hours (2-5 AM)
- App consented by non-admin user
- Multi-tenant app with broad permissions

**Persistence Risks:**
- Inbox rule forwarding to external domain
- Inbox rule deleting emails (hiding evidence)
- Mailbox delegate added
- SMTP forwarding enabled

**Admin Risks:**
- Global Admin role assigned
- Password reset by non-self
- MFA disabled
- Conditional Access policy modified

## Architecture

```
                              Intact.AI Backend Container (Ubuntu)
                                           │
                      ┌────────────────────┴────────────────────┐
                      │         azure_threat_hunter.py           │
                      │                                          │
                      │   ┌─────────────────────────────────┐   │
                      │   │  Microsoft Graph API (Python)   │   │
Azure AD/M365 ────────┼───│  - msal (authentication)        │   │
  (credentials)       │   │  - httpx (async requests)       │   │
                      │   └─────────────────────────────────┘   │
                      │                    │                     │
                      │   ┌────────────────┼────────────────┐   │
                      │   │ SignIn  │ OAuth │ Inbox │ Admin │   │
                      │   │ Module  │ Module│ Module│ Module│   │
                      │   └────────────────┼────────────────┘   │
                      │                    ↓                     │
                      │         Risk Scoring & Correlation       │
                      │                    │                     │
                      └────────────────────┼─────────────────────┘
                                           ↓
                          ┌────────────────┴────────────────┐
                          │    Existing Agentic Pipeline     │
                          │    - LLM Threat Analysis         │
                          │    - Timeline Correlation        │
                          │    - IR Report Generation        │
                          │    - IRIS Case Import            │
                          └──────────────────────────────────┘
```

## Data Format

**Example Finding (Sign-In Risk):**
```python
{
    "_client_id": "azure-tenant-xxx",
    "_hostname": "Azure-M365",
    "FindingType": "SuspiciousSignIn",
    "Severity": "high",
    "Timestamp": "2024-02-21T14:30:00Z",
    "Actor": "admin@company.com",
    "Target": "Azure AD",
    "IPAddress": "185.220.101.xx",
    "Location": "Russia",
    "Indicators": ["TOR exit node", "Impossible travel from US"],
    "Description": "Admin sign-in from TOR exit node in Russia, 2 hours after US login",
    "RiskScore": 95
}
```

**Example Finding (OAuth Abuse):**
```python
{
    "_client_id": "azure-tenant-xxx",
    "_hostname": "Azure-M365",
    "FindingType": "MaliciousOAuthApp",
    "Severity": "critical",
    "Timestamp": "2024-02-20T03:15:00Z",
    "Actor": "user@company.com",
    "Target": "OAuth App: SecureMailReader",
    "AppId": "abc-123-def",
    "Permissions": ["Mail.ReadWrite", "Files.ReadWrite.All"],
    "Indicators": ["Created at 3AM", "Broad permissions", "External publisher"],
    "Description": "OAuth app with mail/file access consented at unusual hour",
    "RiskScore": 90
}
```

## Implementation Plan

### Phase 1: Azure Threat Hunter Service
Create `/modules/backend/services/azure_threat_hunter.py`:

**Dependencies (pip):**
```
msal              # Microsoft auth library
httpx             # Async HTTP client
```

**Key Functions:**
```python
class AzureThreatHunter:
    async def authenticate(self, tenant_id, client_id, client_secret):
        """Get Graph API access token using MSAL"""

    async def hunt_suspicious_signins(self, days_back=30) -> list[dict]:
        """Analyze sign-in logs for risky patterns"""

    async def hunt_oauth_abuse(self) -> list[dict]:
        """Find malicious OAuth apps and consent grants"""

    async def hunt_inbox_rules(self, user_ids=None) -> list[dict]:
        """Detect malicious inbox forwarding/deletion rules"""

    async def hunt_admin_actions(self, days_back=30) -> list[dict]:
        """Find suspicious admin activities"""

    async def run_full_hunt(self, days_back=30) -> dict[str, list[dict]]:
        """Run all detection modules, return grouped findings"""

    def calculate_risk_score(self, finding: dict) -> int:
        """Score finding 0-100 based on indicators"""
```

### Phase 2: Azure IR Blueprints
Create IR-focused blueprints in `blueprint_routes.py`:

```python
AZURE_BLUEPRINTS = [
    {
        "id": "azure_full_hunt",
        "name": "[Azure] Full Threat Hunt",
        "description": "Run all detection modules",
        "modules": ["signins", "oauth", "inbox_rules", "admin_actions"],
        "settings": {"days_back": 30, "min_risk_score": 50}
    },
    {
        "id": "azure_account_compromise",
        "name": "[Azure] Account Compromise Detection",
        "description": "Focus on sign-in anomalies and inbox rules",
        "modules": ["signins", "inbox_rules"],
        "settings": {"days_back": 7}
    },
    {
        "id": "azure_oauth_abuse",
        "name": "[Azure] OAuth/App Abuse",
        "description": "Malicious apps and consent grants",
        "modules": ["oauth"],
        "settings": {}
    },
    {
        "id": "azure_admin_abuse",
        "name": "[Azure] Admin Activity Analysis",
        "description": "Suspicious admin actions, role changes",
        "modules": ["admin_actions"],
        "settings": {"days_back": 30}
    }
]
```

### Phase 3: Pipeline Integration
Modify `services/agentic/pipeline.py` to add Azure IR entry point:

```python
async def run_azure_ir_pipeline(
    blueprint_id: str,
    llm_config: dict,
    azure_credentials: dict,       # tenant_id, client_id, client_secret
    target_users: list[str] = None,  # Optional: focus on specific users
    days_back: int = 30,
    min_risk_score: int = 50
):
    """Run IR pipeline on Azure/M365 environment"""
```

The Azure IR pipeline phases:
1. **Hunt** → Query Graph API for each detection module
2. **Score** → Calculate risk scores for each finding
3. **Filter** → Keep findings above min_risk_score
4. **Analyze** → LLM threat analysis per category
5. **Report** → IR report with IOCs, affected users, recommendations
6. **IRIS** → Import high-severity findings as incident case

### Phase 4: API Routes
Add to `routes/agentic_routes.py`:

```python
@bp.route('/api/agentic/azure/hunt', methods=['POST'])
async def run_azure_hunt():
    """Start Azure threat hunting"""
    # body: {blueprint_id, days_back, target_users}

@bp.route('/api/agentic/azure/investigate-user', methods=['POST'])
async def investigate_user():
    """Deep investigation on specific user"""
    # body: {user_principal_name}

@bp.route('/api/agentic/azure/test-connection', methods=['POST'])
async def test_azure_connection():
    """Test Azure credentials with simple Graph API call"""
```

### Phase 5: UI Integration
Add "Cloud IR" tab to Agentic page:

- **Blueprint selector**: Choose hunt type (Full, Account, OAuth, Admin)
- **Days back**: How far to look (7, 14, 30 days)
- **Target users** (optional): Comma-separated UPNs to focus on
- **Run button**: Triggers hunt, shows streaming results
- **Results**: Same format as Velociraptor - findings → LLM analysis → report

## Files to Create/Modify

| File | Action | Purpose |
|------|--------|---------|
| `services/azure_threat_hunter.py` | CREATE | Graph API queries + risk scoring |
| `services/agentic/pipeline.py` | MODIFY | Add `run_azure_ir_pipeline()` |
| `routes/agentic_routes.py` | MODIFY | Add Azure IR endpoints |
| `routes/blueprint_routes.py` | MODIFY | Add Azure IR blueprints |
| `requirements.txt` | MODIFY | Add `msal`, `httpx` |

## Authentication

Uses existing cloud config (already in system_routes.py):
```python
"azure": {
    "tenant_id": "",
    "client_id": "",
    "client_secret": "",
    "subscription_id": ""  # Not needed for Graph API
}
```

**Required Azure AD App Permissions (Application type):**
| Permission | Why |
|------------|-----|
| `AuditLog.Read.All` | Sign-in logs, directory audits |
| `Directory.Read.All` | Users, apps, service principals |
| `Mail.Read` | Inbox rules analysis |
| `MailboxSettings.Read` | SMTP forwarding detection |

**How to set up in Azure Portal:**
1. Azure AD → App registrations → New registration
2. Certificates & secrets → New client secret
3. API permissions → Add: Microsoft Graph → Application permissions
4. Grant admin consent

## Verification Steps
1. `pip install msal httpx` in backend container
2. Test Azure credentials: `GET https://graph.microsoft.com/v1.0/organization`
3. Run sign-in hunt on test tenant, verify findings
4. Run OAuth hunt, verify app detection
5. Verify LLM produces actionable IR analysis
6. Confirm IRIS case creation with timeline

## Sources
- [Microsoft Graph Sign-In Logs](https://learn.microsoft.com/en-us/graph/api/signin-list)
- [Microsoft Graph Audit Logs](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list)
- [Microsoft Graph Service Principals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list)
- [CISA Sparrow Detection Logic](https://github.com/cisagov/Sparrow) (reference for what to detect)
