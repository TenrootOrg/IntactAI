# AWS pipeline — mirror Azure, native CloudTrail (boto3) + SIGMA

> **Superseded note:** the original plan proposed wrapping an external
> posture scanner as the AWS state/posture source. The shipped design
> instead uses **CloudTrail (native boto3 collection) + SIGMA** for events
> and detection, with GuardDuty / AccessAnalyzer / IAM-principals as the
> other native boto3 sources. References below to that external scanner are
> historical; read them as "CloudTrail (native) + SIGMA".

## Context

We have a complete Azure security pipeline (`modules/backend/services/azure/`,
`routes/azure_routes.py`, agentic skills, dashboard tab). The dashboard
already has a sidebar entry `Cloud → AWS` and a Settings form for
`access_key_id` / `secret_access_key` / `region` / `session_token`,
but every other AWS surface is either a stub or absent. SIGMA rules for
AWS already exist at `/opt/sigma-rules/rules/cloud/aws/` (~55 rules
across CloudTrail / IAM / S3 / GuardDuty signals).

Goal: build the AWS-side mirror so the dashboard can do the same online/
offline scan flow for AWS that it does for Azure today, reusing every
generic part (SIGMA runner, agentic analyzer, IRIS export, report
storage, workflow row machinery) and replacing only the cloud-specific
collection layer.

## Tooling comparison — which OSS tool plays DFIR-O365RC's role for AWS?

The Azure pipeline wraps **DFIR-O365RC** (ANSSI-FR, 282 ⭐, last push 2025-09-22)
in a Docker container as our state-and-audit-log collector. The user
asked to identify the equivalent mature, actively-maintained tool for
AWS. Fresh GitHub stats pulled today, plus role suitability for a
DFIR/SOC pipeline:

| Tool | Stars | Last push | What it does | Fit for our pipeline |
|---|---:|---|---|---|
| **Prowler** ([prowler-cloud/prowler](https://github.com/prowler-cloud/prowler)) | **13,750** | **2026-05-07** | 572 AWS posture checks across 83 services, 41 compliance frameworks, OCSF JSON output, Docker image, CLI. Now powers attack-path graph via Cartography integration. | ⚠️ **Evaluated, not shipped.** Strong posture scanner, but adds an external image dependency for coverage beyond DFIR triage. Shipped design derives state/posture natively from boto3 (CloudTrail + SIGMA, AccessAnalyzer, IAM principals) instead. |
| **Steampipe** ([turbot/steampipe](https://github.com/turbot/steampipe)) | 7,808 | 2026-04-24 | SQL queries over 153 cloud-API plugins, 2,000+ tables. Excellent for ad-hoc IR queries. | Too unstructured for an automated pipeline. Better as an analyst tool. |
| **ScoutSuite** ([nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite)) | 7,648 | 2025-09-23 | Multi-cloud audit, ~200 checks. | Once a strong choice; cadence has slowed sharply (8+ month gap mid-2025 per public commentary, despite the 2025-09 commit). Prowler has surpassed it on every dimension. |
| **CloudQuery** ([cloudquery/cloudquery](https://github.com/cloudquery/cloudquery)) | 6,398 | 2026-05-06 | ELT cloud asset normalization → data warehouse. | Designed for SQL-warehouse ingestion. Heavyweight; we'd discard most of its value. |
| **Pacu** ([RhinoSecurityLabs/pacu](https://github.com/RhinoSecurityLabs/pacu)) | 5,173 | 2026-04-27 | Post-exploitation framework. | Offensive/red-team. Wrong use case. |
| **Cartography** ([cartography-cncf/cartography](https://github.com/cartography-cncf/cartography)) | 3,875 | 2026-05-07 | Neo4j asset graph; CNCF-incubating. | Already integrated *into* Prowler's Attack Paths feature — we get the graph for free if we wrap Prowler. |
| **CloudFox** ([BishopFox/cloudfox](https://github.com/BishopFox/cloudfox)) | 2,375 | 2026-04-21 | Per-principal blast-radius enumeration. Go binary, lightweight. | Excellent **complement** for IR scenarios ("what can this compromised key access?"). Add as v2 supplement, not replacement. |
| **PMapper** ([nccgroup/PMapper](https://github.com/nccgroup/PMapper)) | 1,551 | 2024-08-02 | IAM permission graph. | Aging (no commits in ~2 years). Skip. |
| **TrailScraper** ([flosell/trailscraper](https://github.com/flosell/trailscraper)) | 834 | 2026-05-07 | CLI for slicing CloudTrail JSON exports. | Niche/complementary; we can replicate its filtering with ~30 lines of boto3. Not worth the wrapper. |
| **Cloud-Forensics-Utils** ([google/cloud-forensics-utils](https://github.com/google/cloud-forensics-utils)) | 503 | 2026-05-05 | Multi-cloud DFIR (EBS snapshot, IAM enumeration). | Smaller community, narrower scope. Could pull specific helpers but not worth wrapping the whole library. |
| **DFIR-O365RC** *(baseline)* | 282 | 2025-09-22 | Azure/M365 audit log collector — what we wrap today. | Reference point only. |
| **Diffy** ([Netflix-Skunkworks/diffy](https://github.com/Netflix-Skunkworks/diffy)) | 630 | 2024-01-11 | DFIR triage. | **Dormant.** Skip. |

**Recommendation (shipped): CloudTrail (native boto3) + SIGMA is the AWS
core.** Rather than depending on an external posture scanner, the AWS
module collects raw events with plain boto3 (`cloudtrail.lookup_events`,
`guardduty.list_findings`, `accessanalyzer.list_findings`, IAM-principal
enumeration) and runs them through the same SIGMA → analyzer → report
pipeline Azure uses. This keeps the AWS surface dependency-free (no extra
container image to pin/pull) and gives event-level detail SIGMA can match
against.

**Posture / state** is derived natively too: AccessAnalyzer findings and
IAM-principal enumeration fold into the `INV.*` finding buckets as
state-snapshots, the same way Azure wraps CA policies / federation.

**Optional v2 supplement: CloudFox** for IR scenarios where the
operator wants per-principal blast-radius enumeration. Tiny binary
(~30 MB), trivial to wrap. Defer to phase 4.

## Strategy

**Mirror the Azure module structure 1-for-1. Use plain boto3 for raw
CloudTrail event collection (the SIGMA-matching path) plus GuardDuty /
AccessAnalyzer / IAM-principal enumeration; derive state/posture natively
from those sources. Ship in three phases so each is independently
testable.**

The Azure pipeline's shape works because it factors collection from
detection from analysis from report from IRIS. AWS gets the same factor:

```
phase 1 validation -> phase 2 collection
   ├─ raw events    : boto3 cloudtrail.lookup_events  (analog of MS Graph signin/audit)
   └─ state/posture : boto3 AccessAnalyzer + IAM-principal enumeration
   -> phase 3 time filter
   -> phase 4 SIGMA detection (existing rules at /opt/sigma-rules/rules/cloud/aws/)
   -> phase 4b CloudTrail event-name pre-detection (parallel to UAL pre-detect)
   -> phase 4c state-snapshot wrapping from AccessAnalyzer + IAM findings
   -> phase 5 LLM analysis (with pipeline_kind="aws")
   -> phase 6 AWS-formatted report
   -> phase 7 IRIS import (existing, generic)
```

**Why native boto3 state collection (shipped decision):** rather than
add an external posture-scanner dependency (extra image to pin/pull, a
Docker-subprocess wrapper to maintain), the module derives posture from
the boto3 sources it already collects — AccessAnalyzer findings and
IAM-principal enumeration folded into `INV.*` state-snapshot buckets.
This keeps the AWS surface self-contained and event-level, at the cost
of the broader compliance-framework coverage an external scanner would
have added (out of scope for DFIR triage).

Auth scope for v1: **single account, long-lived access key + optional
session token** (matches what Settings already collects). Cross-account
AssumeRole is a v2 follow-up — don't block initial delivery on it.

Region scope for v1: **multi-region by default**, with a region picker
in the UI defaulting to the configured `region` field plus an "all
enabled regions" option. CloudTrail's global-service events (IAM,
STS, console login) come back from `us-east-1` regardless; per-service
events (EC2, S3, Lambda) need per-region queries.

## Critical files — what to create / modify

### A. Backend services (new directory `modules/backend/services/aws/`)

| File | Mirrors | Responsibilities |
|---|---|---|
| `__init__.py` | `azure/__init__.py` | Re-exports |
| `collectors.py` | `azure/collectors.py` | `LOG_SOURCES` dict, `collect_aws_logs()`, `parse_uploaded_logs()`, **boto3-only** per-source collectors for events + state (`cloudtrail.lookup_events`, `guardduty.list_findings`, `accessanalyzer.list_findings`, IAM-principal enumeration), `detect_source_type()` for offline. State-snapshot posture is derived from AccessAnalyzer + IAM findings. |
| `cloudtrail_runner.py` | `azure/dfir_o365rc.py` (role) | Native boto3 CloudTrail `LookupEvents` collector. `is_available(aws_config)` (creds configured), `collect_cloudtrail(...)` returns IntactAI-shaped records. Light/full mode parallel: `cloudtrail_mode="light"` collects only the high-signal event names; `"full"` paginates everything up to a cap. |
| `pipeline.py` | `azure/pipeline.py` | `run_aws_pipeline()`, `run_aws_on_existing()`, `_run_post_collection_phases()`. Reuses `services.agentic.analyzers.analyze_artifacts` with `pipeline_kind="aws"`. Phase 2 calls `collect_aws_logs()` for events + state; phase 4c wraps AccessAnalyzer + IAM findings as state snapshots. |
| `reports.py` | `azure/reports.py` | `generate_aws_report()`, `save_aws_report()`. New AWS-flavored system prompt (CloudTrail event semantics, IAM permissions, GuardDuty finding types, SIGMA rule matches, MITRE ATT&CK Cloud Matrix). |

**Sources** (the AWS analog of `LOG_SOURCES`):

Event sources collected via **boto3** (raw events for SIGMA matching):

| Source ID | sigma_prefix | boto3 client | Notes |
|---|---|---|---|
| `cloudtrail_console` | `AWS.CloudTrail.Console` | `cloudtrail` | `lookup_events` filtered to `EventName == 'ConsoleLogin'` (global, queried in us-east-1) |
| `cloudtrail_iam` | `AWS.CloudTrail.IAM` | `cloudtrail` | `lookup_events` filtered to `EventSource == 'iam.amazonaws.com'` |
| `cloudtrail_full` | `AWS.CloudTrail` | `cloudtrail` | `lookup_events` unfiltered, multi-region; high volume — covered by `cloudtrail_mode` analog |
| `guardduty_findings` | `AWS.GuardDuty` | `guardduty` | `list_findings` + `get_findings`, multi-region |
| `accessanalyzer_findings` | `AWS.AccessAnalyzer` | `accessanalyzer` | `list_findings` per analyzer per region |

State / posture sources collected natively via **boto3** (folded into `INV.*` state-snapshot buckets):

| Source ID | sigma_prefix | boto3 client | Notes |
|---|---|---|---|
| `iam_principals` | `AWS.IAM` | `iam` | IAM users / roles / access keys / effective-admin (CloudFox-equivalent) |
| `accessanalyzer_findings` | `AWS.AccessAnalyzer` | `accessanalyzer` | external/public access findings per analyzer per region |

**`ual_mode` analog → two knobs**, one per collection axis:

* **`cloudtrail_mode`**: `light` (default for big accounts:
  `cloudtrail_console` + `cloudtrail_iam` only; same idea as Azure's
  light UAL) or `full` (multi-region unfiltered).

### B. Backend route `modules/backend/routes/aws_routes.py` (new)

Mirror every endpoint shape from `azure_routes.py`. Substitute `aws` for
`azure` in paths and identifiers:

```
GET  /api/aws/status
GET  /api/aws/blueprints
GET  /api/aws/sources
GET  /api/aws/rules
POST /api/aws/scan
POST /api/aws/upload
POST /api/aws/analyze-offline
GET  /api/aws/status/<rid>
GET  /api/aws/results/<rid>
GET  /api/aws/findings/<rid>
GET  /api/aws/analysis/<rid>
GET  /api/aws/runs
GET  /api/aws/report/<rid>/download
GET  /api/aws/report/<rid>/types
GET  /api/aws/data/<rid>/download
```

Register `aws_bp` in `routes/__init__.py`. Body shape for `/api/aws/scan`:

```json
{
  "blueprint": "aws_quick_triage",
  "regions": ["us-east-1", "eu-west-1"],
  "time_filter": {"type":"relative","value":"24h"},
  "scope_mode": "targeted" | "account_wide",
  "target_principals": ["arn:aws:iam::...:user/X"],
  "cloudtrail_mode": "light" | "full",
  "enable_llm": true,
  "min_severity": "medium"
}
```

### C. Generic helper extractions (small refactor)

Two Azure-side helpers should move up so AWS can reuse:

- `services/azure/sigma_runner.py:run_sigma_rules` — already
  provider-agnostic apart from the rule-load path. Either parameterize
  `load_azure_rules` to take a category (`cloud/azure` vs `cloud/aws`)
  or duplicate the loader in `services/aws/sigma_runner.py`. Pick
  parameterize — drops ~30 lines vs duplicate.
- `services/agentic/analyzers.py:analyze_artifacts` already accepts
  `pipeline_kind`. Add `"aws"` as a valid value alongside `"azure"`.

### D. Agentic skills (new files mirror the Azure pair)

- `modules/backend/services/agentic/skills/dfir/intact-aws-cloud-investigation.md`
  — atomic skill covering CloudTrail event semantics, IAM principal
  shapes, GuardDuty finding-type taxonomy, AssumeRole chain reading,
  state vs event discipline, MITRE ATT&CK Cloud Matrix coverage.
- `modules/backend/services/agentic/skills/macros/intact-investigating-aws-account-compromise.md`
  — macro playbook with the AWS-specific 5-step investigation arc:
  initial access (ConsoleLogin / API key compromise) → privilege
  escalation (IAM policy changes, AssumeRole) → persistence (new
  IAM users, access keys, SAML providers) → defense evasion
  (CloudTrail/GuardDuty deletion) → blast radius (which resources
  the compromised principal can touch).
- `modules/backend/services/agentic/skills/artifact_map_overrides.yaml`
  — append a new section pinning `AWS.*`, `GD.*` (GuardDuty), `IAM.*`
  patterns to `intact-aws-cloud-investigation`. Same shape as the
  existing Azure section.

### E. Backend dependency

Add `boto3>=1.35` and `botocore>=1.35` to `modules/backend/requirements.txt`.
Pin to a recent stable; verify it builds against the existing Python
3.12 image.

### F. Frontend `modules/nginx/html/index.html`

Replace the existing "Cloud > AWS" stub block with a full interactive
tab mirroring the Azure tab (lines 1709–1726 today are the stub):

State vars to add (in the existing Alpine `x-data`):
```
awsMode: 'online' | 'offline'
awsBlueprint: 'aws_quick_triage' (default)
awsBlueprints: []
awsRegions: ['us-east-1']  // multi-select
awsTimeFilter: '24h'
awsCustomStart, awsCustomEnd: ''
awsMinSeverity: 'medium'
awsTargetPrincipals: ''  // comma-separated ARNs
awsScopeMode: 'targeted' | 'account_wide'
awsCloudTrailMode: 'light' | 'full'
awsEnableLLM: false
awsRunning, awsRunId, awsResults, awsUploadedFiles
```

Methods: `checkAwsStatus()`, `startAwsScan()`, `uploadAwsFiles()`,
`analyzeAwsOffline()` — all 1:1 with their Azure equivalents.

Settings form: the existing fields at index.html ~line 2540 already
handle credentials. Verify they render and post correctly to
`/api/config/cloud`.

### G. Default blueprints

Add to `modules/backend/services/aws/pipeline.py:get_aws_blueprints()`
following the Azure pattern. Four blueprints to start:

| ID | Description |
|---|---|
| `aws_quick_triage` | Last 24h, light CloudTrail (console + IAM), GuardDuty current-region |
| `aws_account_investigation` | Targeted by principal ARN, full CloudTrail multi-region |
| `aws_privilege_escalation` | IAM policy changes + AssumeRole chains, last 7d |
| `aws_full_investigation` | Everything, all enabled regions, last 30d |

### H. Storage / persistence

- `data/aws_runs/<rid>.json` — full run state (mirrors `data/azure_runs/`).
- Reuse the report-store DB layer for AWS reports (same pattern as Azure).
- Gitignore both paths in `.gitignore`.

### I. Documentation

- `docs/AWS_AUTOMATION.md` — operator guide: required IAM permissions
  (read-only audit roles), recommended trail setup, region-coverage
  notes, performance expectations on large accounts, cost notes.
- Mention in `docs/SECRETS.md` that AWS keys live in
  `data/frontend_data.db` under `cloud.aws.*` (same pattern as Azure).

## Phasing — three deliverable slices

| Phase | What ships | Verifiable how |
|---|---|---|
| **1. Backend skeleton** | `services/aws/{collectors,pipeline,reports}.py`, `state_collector.py`, `routes/aws_routes.py`, `boto3` dependency, blueprint definitions, generalized SIGMA loader. UI stays a stub. | curl POST `/api/aws/scan` against a real test account, watch the workflow row populate, download Data ZIP, verify CloudTrail events present + at least one SIGMA finding. |
| **2. Frontend + offline** | Replace UI stub with the full interactive tab. Wire offline upload (raw CloudTrail JSON files or `.gz` archives from a S3 trail). | Run the same scan from the dashboard; upload a CloudTrail `.json.gz` from a known-tainted account, get same findings as in phase 1. |
| **3. AWS-tuned LLM + IRIS + docs** | Drop the two new agentic skill files; pin AWS artifacts in `artifact_map_overrides.yaml`; AWS-specific report system prompt; `docs/AWS_AUTOMATION.md`. | LLM analysis output references AWS-specific TTPs (AssumeRole chain, IAM PassRole, etc.); IRIS export creates a case with AWS IOCs; docs review. |

Total estimate: phase 1 ~600 LOC of Python (mostly boilerplate following
the Azure template), phase 2 ~150 LOC of HTML/Alpine, phase 3 ~400
words of skill markdown + 200 LOC of report prompt.

## Verification (end of phase 1, must pass before phase 2 starts)

1. **Backend boots clean** — `docker logs intact_backend` shows no
   import errors after restart, `/api/aws/status` returns 200 with
   the credential-configured flag.
2. **CloudTrail collection works** — POST to `/api/aws/scan` with a
   24h window against a test account; the workflow log shows
   `[AWS] CloudTrail.Console: N records`, `[AWS] CloudTrail.IAM:
   M records`. Counts match what `aws cloudtrail lookup-events`
   returns from the CLI for the same window.
3. **SIGMA matches fire** — at least one of the 55 AWS rules at
   `/opt/sigma-rules/rules/cloud/aws/` matches a real event in the
   collected data. `[AWS] SIGMA detection complete: K findings`.
4. **State snapshots collected** — `[AWS] Added N state-snapshot
   findings from 3 sources` (IAM principals, IAM policies, S3 bucket
   policies).
5. **Data ZIP intact** — `GET /api/aws/data/<rid>/download` returns
   a ZIP with `collected/AWS.CloudTrail.Console.json` etc., file
   sizes > 0, JSON valid.
6. **Cancellation works** — long-running scan can be cancelled via
   the existing `is_cancelled(run_id)` mechanism (same as Azure).

## Out of scope for v1

- **Cross-account AssumeRole** chains. Scope is single account using
  long-lived credentials. Add later as a `cloud.aws.assume_role_arn`
  field + an STS-assume step in the auth path.
- **Real-time CloudTrail Lake / EventBridge** ingestion. v1 uses the
  per-call `lookup_events` API + offline JSON upload. Lake is a v2
  performance optimization.
- **Org-mode hardening checks** (CIS benchmarks against an
  Organizations-level structure). Out of scope; covered by
  third-party tools (Prowler, ScoutSuite) — add as an "import these
  reports" feature later if there's demand.
- **VPC flow logs / Athena queries**. Volume is enormous; not the
  same shape as the other event sources. Defer.

## Critical files (cheat sheet)

New:
- `modules/backend/services/aws/__init__.py`
- `modules/backend/services/aws/collectors.py`
- `modules/backend/services/aws/pipeline.py`
- `modules/backend/services/aws/state_collector.py`
- `modules/backend/services/aws/reports.py`
- `modules/backend/routes/aws_routes.py`
- `modules/backend/services/agentic/skills/dfir/intact-aws-cloud-investigation.md`
- `modules/backend/services/agentic/skills/macros/intact-investigating-aws-account-compromise.md`
- `docs/AWS_AUTOMATION.md`

Modified:
- `modules/backend/routes/__init__.py` — register `aws_bp`
- `modules/backend/requirements.txt` — add `boto3`, `botocore`
- `modules/backend/services/agentic/skills/artifact_map_overrides.yaml`
  — append AWS section
- `modules/backend/services/agentic/analyzers.py` — accept
  `pipeline_kind="aws"` alongside existing values
- `modules/backend/services/azure/sigma_runner.py` (or a new shared
  module) — generalize the rule-loader to take a category
- `modules/nginx/html/index.html` — replace the AWS stub block with
  the full interactive tab; add state vars
- `.gitignore` — `data/aws_runs/`
