# Log-data detection: status and how to resume

Where the work on detecting attacks in **case attachments that carry log data**
(SIEM, firewall, EDR, IdP, proxy, cloud audit) stood on 2026-10-18, when it was
parked for a release. Read this before picking it up again.

## What it does

An attachment of log data is read generically (format, columns, normalized fields),
then checked by three things. Only rows rated medium or higher become fusion events.

1. **Vendor verdicts**: the product's own alert fields (`config/external_log_rules.yaml`, native rules).
2. **Sigma**: SigmaHQ's public rules plus 1,174 of Splunk's detections translated to Sigma (638 medium+, 536 low)
   (`config/sigma-escu/`). Engine: `services/fusion/sigma_eval.py`.
3. **Behaviour rules**: patterns no single event shows, such as brute force, beaconing,
   Kerberoasting, AD permission changes, M365 persistence and bursts of low signals
   (`services/fusion/behaviour.py`).

## Where it stands

| Measure | Value |
|---|---|
| Splunk attack recordings detected (medium+) | **897 of 1,275 (70%)**, up from 637 (49%) |
| ATT&CK techniques with a detected recording | **261 of 310 (84%)**, up from 222 (71%) |
| Benign Windows corpus (1.24 M events) | **44 detections, 0 bursts**, mostly real admin actions |
| Real benign web (500k Squid, 7k Apache) | 0 web-rule hits; Squid gives 2 beaconing detections in all |
| Installed rules still firing on their own recording | 1,174 of 1,174 (9d699cc6 added 16, each proved) |

Per source: see "Coverage on Splunk attack_data" in `docs/EXTERNAL_LOG_TEST_DATASETS.md`.

## What is tested, and against what

| Source | Attack recordings | Normal (benign) data |
|---|---|---|
| Windows events (Security, Sysmon, System, Application, PowerShell, AppX) | 79% | yes: 1.24 M events |
| Web servers / proxies (nginx, Squid) | 73% | yes: 500k Squid, 7k Apache |
| ESXi syslog | 82% | none |
| Google Workspace login / admin | 80% | Elastic sample only |
| Duo admin | 72% | none |
| Okta | 71% | Elastic sample only |
| Entra ID | 70% | Elastic sample only |
| Linux auth / Sysmon / auditd | 66% / 64% / 55% | none |
| Suricata | 63% | competition traffic only |
| Office 365 audit | 62% | none |
| AWS CloudTrail / Security Lake | 47% / 52% | Elastic sample only |
| osquery | 47% | none |
| Cisco Secure Firewall (eStreamer) | 16 of 17 rules fire | none |
| Cisco ASA / FTD | 11 of 12 rules fire | Elastic sample (1 hit, kept low) |
| Kubernetes audit, Zscaler, GitHub audit | rules fire on their recordings | none |

**No benign data** means the false-alarm rate there is unknown. The single most
useful next step is a day or two of normal logs from a real or lab tenant (M365,
AWS, Linux with auditd), measured with `scripts/dev/detection_harness/benign_files.py`.

## The process (each rule earns its place)

1. **Translate**: `scripts/dev/escu_to_sigma.py <sc.jsonl> <out_dir>`. It translates only
   plain conditions, and it skips a detection rather than dropping a condition it cannot express.
2. **Prove**: `scripts/dev/escu_prove.py <rules_dir> <out.jsonl> [i/3]`. A rule ships only if
   it fires on the recording its detection names. The prover reads files exactly as `ingest` does.
3. **Benign check**: `scripts/dev/escu_benign.py` (Windows corpus) and `detection_harness/benign_files.py`
   (log files). A rule that fires on normal data ships **low and out of bursts**.
4. **Install**: `scripts/dev/escu_install.py <rules_dir> <benign1.json,...> <prove_latest.jsonl>`.
5. **Commit**: one commit per fix, with tests. Gate the commit on the real test exit code.
   Then deploy (`scripts/dev/push_backend.sh`, plus `docker cp` for `config/`) and check on the box.

After any change to the reader (`external_logs.py`), re-run coverage
(`detection_harness/run_cov.py`) and look at the top rule names for odd ones.
New `_flat` columns change column detection for every product: twice a field became
a fake severity or rule. Fields that only rules need belong in `rule_fields()`.

## Shipped since this was parked (in main, release intact-20261020)

The WIP commit d12c59e7 is in main, made safe by 9d699cc6:

1. **Wildcard fix** (`sigma_eval._has_wild`): `\\*` (a backslash, then a wildcard) is now a
   wildcard. The 28 rules it made fire on benign Windows data (raw disk volume access 3,589,
   default-icon registry 1,048, script in temp 969, ...) are low and out of bursts.
2. **The 13 parked rules are installed** (Chrome / Discord credential-store access, Office
   loading VBE7 / MSHTML / taskschd, RDP sessions, WinSCP config, product-key query), plus
   InstallUtil credential theft, Outlook credentials in the registry, two Socat rules and a web
   server spawning a shell.
3. Translator: Windows add-on field names, the OS taken from the detection's test data,
   "any OS" rules.

The coverage figures above predate 9d699cc6; re-run `detection_harness/run_cov.py` before
quoting new ones.

## By severity: can each SigmaHQ rule fire? (branch `threshold-engine`, 2026-10-20)

Worked in severity order (critical, then high, then medium). A rule counts as
reachable when some row we read -- real data, or one row per source fixed from the
vendor's documented shape -- gets its log source. Measured by the same script on
both sides:

| Level | main | threshold-engine |
|---|---|---|
| Critical | 167 / 176 (94.9%) | **176 / 176** |
| High | 1,635 / 1,716 (95.3%) | **1,716 / 1,716** (3 Zeek smb_files: no sample here, the profile is tested) |
| Medium | 1,361 / 1,412 (96.4%) | **1,398 / 1,412** (99.0%; 7 FortiGate + 4 Zeek smb_files: no sample here, the profiles are tested) |

What closed the gaps: AV/EDR detections as antivirus rows; PrintService, DNS-server
analytic, SmbClient channels and Sysmon 255/16; Bitbucket audit; OpenCanary; RPC
Firewall; Entra PIM alerts; application and web-server error logs (and Log4j logs
misread as two-column CSV); Cisco command accounting, IOS XE / FortiOS / PAN-OS
indicators, Zeek rdp / x509; Winlogbeat's winlog.event_id.

Reachable is not the whole story: `services/fusion/edr_telemetry.py` reads Defender
XDR, CrowdStrike FDR, Carbon Black Cloud, Elastic Defend and SentinelOne events per
event type, so their file (15 critical), registry (11), pipe (8), image-load, DNS,
network and process-access events reach the rules Sysmon alone fed -- and an EDR's
logon or connection is no longer guessed into a process creation.

Every step was checked both ways on real data (all rules over the datasets, main
vs branch): what changed was a real detection gained or a false one removed.

Medium tier since: FortiGate configuration events, Windows file_access (Security 4663,
Elastic Defend), Kubernetes rules filed under `application`, Google Workspace login
(Reports API rows read with Cloud Logging's field names), O365 Management Activity
read with SigmaHQ's eventSource / eventName / status (on 9,189 real O365 rows: 8 hits
became 55, all of them Microsoft's own alerts or real admin changes), Django / Rails
error logs, and 10 Splunk count rules on the correlation engine.

Then file_rename from the EDRs that log the old name (Defender FileRenamed, Elastic
rename, SentinelOne File Rename; a rename stays a file_event too) and Sysmon 27-29.

Then 25 more Splunk count rules (35 in all; these 25: 12 medium, 13 low), each fired on its own
recording and checked on the benign corpus. The translator now reads tstats' `BY _time
span=1m` as the window (it was taken for a field), drops a group-by field the search
pins to one value, counts `dc(_raw)` as events, and has each source's raw name for the
add-on's group-by fields (`GROUP_FIELDS_BY_SOURCE`: Windows / Sysmon signature and
action from the EventID, O365 ClientIP / UserId, Okta, Google Workspace, Cisco). The
engine reads Windows `status` from the audit keyword, as Splunk's add-on does.
Not shipped: 2 Cisco intrusion counts and forfiles (by Splunk's own grouping their
threshold is never met on the recording), an O365 count on `record_type` text (the raw
log has a number), the /etc deletion count (grouped by vendor_product), and two mass
file-deletion counts (they fire on the benign corpus: Explorer deleting a folder).

Low tier: 275 of 281 low rules had a row; the last six are router BGP / LDP MD5
failures (Cisco, Huawei, Juniper syslog) and OneLogin's Events API -- tested on rows
written from the vendors' formats only, no real sample here.

Found on the way, checked on all real data (800,890 rows, every rule before vs after):
- SigmaHQ's field-less `'|all': [...]` keywords were read as a field named "", so 17
  rules could never fire (4 critical: ProxyLogon / ProxyShell, IIS CVE-2021-26858).
- Splunk's classic Windows event text (a timestamp line, then Key=Value lines) was read
  line by line. Splunk's own ProxyShell recording gave 0 rows; read as records, it gives
  4 critical "Mailbox Export to Exchange Webserver" and 2 high hits.
- The only other change on all real data: "Credentials In Files - Linux" 0 -> 124 high,
  all of them the recorded attack (grep for password / secret / token keys).

"Reachable" (a row gets the log source) is not "fireable": `field_audit` found 58
SigmaHQ rules (1 critical, 16 high, 36 medium) whose fields no real row of their source
carries -- Azure properties.message, GCP gcp.audit.method_name, Google Workspace
eventName, ... Next step.

Still open, medium tier: the remaining Splunk threshold detections ("logic after the
filter" or a source with no reader). Left out on purpose: the database keyword rule
("drop" / "select *" fire on every query log), Python exceptions (too generic to tell
from any other Python log), PAN-OS GlobalProtect file creation (no log carries it).

## Next, in order of value

1. **Benign data** for the cloud and Linux sources (see above).
2. **Threshold engine**: about 190 Splunk detections are "count over a window" (password
   spray, many failed MFA, mass share access). This is the largest gain left
   (about +5 to 6% coverage, 2 to 3 days).
3. Entra service-principal cases (admin-consent bypass, SP privilege escalation, owner added).
4. Sources with no reader or rules yet: Cisco NVM / Isovalent / IOS / SD-WAN, IIS, CloudFront,
   CrushFTP, O365 message trace, CrowdStrike identities, PingID.
5. Baseline detections ("first time this user / region"): these need per-tenant history.

Left out on purpose: mass file deletion / creation counts (Explorer deleting a folder
looks the same) and ransom-note name lists (a list someone has to maintain).

## SigmaHQ is in the backend image (since this release)

The Dockerfile bakes the SigmaHQ release pinned at `versions.sigma_rules` into
`/app/sigma-rules`, and sets `SIGMA_RULES_DIR`, which every reader uses (AWS, Azure,
log data). This replaced the installer's git clone, which gave no rules offline or with
both cloud modules off, and the `aws_sigma` release asset (AWS rules only), which is no
longer built. An upgrade from an older release finds no `aws_sigma` asset and skips it.
`versions.aws_sigma` stays only for that bookkeeping. To refresh the rules, bump
`versions.sigma_rules` and rebuild the image.

## Data (never in the repo)

`~/datasets/splunk-attack-data/` (recordings), `.../_work/` (`sc.jsonl`, `meta.jsonl`,
`prove_latest.jsonl`, `results/`), `~/datasets/work/flat/benign_nextron_*` (benign Windows)
and `~/datasets/external-logs/` (vendor samples, real benign web). The harness is
described in `scripts/dev/detection_harness/README.md` (branch `detection-coverage`).
