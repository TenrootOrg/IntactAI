"""
AWS Log Collection Module — SCAFFOLD

In this scaffold, every per-source collector returns hand-curated fixture
data from `fake_data/*.json`. The function signatures, return shapes,
LOG_SOURCES dict, and the `collect_aws_logs()` orchestration are the same
shape as `services.azure.collectors` so the upstream pipeline doesn't
know it's looking at fake data.

When real tool integrations are wired in (boto3 / Prowler / etc.), each
`_collect_<source>_fake()` function becomes a thin caller of the real API
— that's the only edit needed; pipeline, sigma_runner, reports, and the
routes don't change.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from services.workflow_service import add_log_to_run, is_cancelled

_FAKE_DATA_DIR = Path(__file__).parent / "fake_data"


# =============================================================================
# LOG_SOURCES — provider-agnostic source registry
# =============================================================================
#
# Mirrors `services.azure.collectors.LOG_SOURCES`. Each source is one
# logical query a real collector would make (e.g. "CloudTrail filtered to
# console logins"). `sigma_prefix` is what gets written into each record's
# `EventSource` field at normalisation time so SIGMA rules can target by
# vendor.

LOG_SOURCES: Dict[str, Dict[str, Any]] = {
    # Tier 1: AWS-native detections (low volume, high value)
    'guardduty_findings': {
        'name': 'GuardDuty Findings',
        'sigma_prefix': 'AWS.GuardDuty',
        'tier': 1,
        'fixture': 'fake_guardduty_findings.json',
    },
    'accessanalyzer_findings': {
        'name': 'IAM Access Analyzer Findings',
        'sigma_prefix': 'AWS.AccessAnalyzer',
        'tier': 1,
        'fixture': 'fake_accessanalyzer_findings.json',
    },
    # Tier 2: CloudTrail event slices (targeted)
    'cloudtrail_console': {
        'name': 'CloudTrail — Console Login Events',
        'sigma_prefix': 'AWS.CloudTrail',
        'tier': 2,
        'fixture': 'fake_cloudtrail_console.json',
    },
    'cloudtrail_iam': {
        'name': 'CloudTrail — IAM Events',
        'sigma_prefix': 'AWS.CloudTrail',
        'tier': 2,
        'fixture': 'fake_cloudtrail_iam.json',
    },
    # Tier 3: CloudTrail full multi-region (high volume)
    'cloudtrail_full': {
        'name': 'CloudTrail — All Events',
        'sigma_prefix': 'AWS.CloudTrail',
        'tier': 3,
        'fixture': 'fake_cloudtrail_full.json',
    },
    # Tier 4: State / posture snapshots (Prowler-shaped, no event timeline)
    'prowler_posture': {
        'name': 'Prowler Posture Findings',
        'sigma_prefix': 'AWS.Prowler',
        'tier': 4,
        'fixture': 'fake_prowler_posture.json',
    },
    'iam_principals': {
        'name': 'IAM Principals + Keys (CloudFox-equivalent)',
        'sigma_prefix': 'AWS.IAM',
        'tier': 4,
        'fixture': 'fake_iam_principals.json',
    },
}


# =============================================================================
# Fixture loader (the stub backend for every source in this scaffold)
# =============================================================================


def _load_fixture(filename: str) -> List[Dict]:
    """Load a fixture JSON file shipped under `fake_data/`. Returns a list
    of records. The fixture format is just a JSON array of objects."""
    path = _FAKE_DATA_DIR / filename
    if not path.exists():
        return []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and 'records' in data:
            return data['records']
        return []
    except Exception:
        return []


def _stub_collect(
    source: str,
    log: Callable[[str, str], None],
    aws_config: Optional[Dict[str, Any]] = None,
    regions: Optional[List[str]] = None,
    resource_arn: Optional[str] = None,
    target_principal_arns: Optional[List[str]] = None,
    time_filter: Optional[Dict[str, Any]] = None,
    is_cancelled_func: Optional[Callable[[], bool]] = None,
    max_principal_age_days: Optional[float] = None,
    max_access_key_age_days: Optional[float] = None,
) -> List[Dict]:
    """Collect records for one source. If a real runner exists for this
    source AND `aws_config` is provided, run it; on empty/failure fall
    back to the bundled fixture so the rest of the pipeline still has
    shape-correct data to work on.

    The fallback is intentional: it keeps the dev/demo flow (no AWS creds)
    working and gives us a deterministic "what does a clean run look like"
    baseline that doesn't depend on a customer's account."""
    cfg = LOG_SOURCES.get(source)
    if not cfg:
        log(f"[AWS] Unknown source: {source}", "warning")
        return []
    sigma_prefix = cfg.get('sigma_prefix', 'AWS')

    # --- Real-runner path (Prowler) -----------------------------------
    if source == 'prowler_posture' and aws_config:
        try:
            from . import prowler_runner
            avail = prowler_runner.is_available()
            if avail.get('available'):
                records = prowler_runner.run_prowler_scan(
                    aws_config,
                    services=['iam', 'cloudtrail', 'guardduty', 's3', 'accessanalyzer'],
                    severities=['critical', 'high'],
                    regions=regions,
                    resource_arn=resource_arn,
                    fail_only=True,
                    log_func=log,
                    is_cancelled_func=is_cancelled_func,
                )
                if records:
                    for r in records:
                        r.setdefault('_source', source)
                        r.setdefault('EventSource', sigma_prefix)
                    log(f"[AWS] {cfg['name']}: {len(records)} live findings (Prowler)", "info")
                    return records
                log(f"[AWS] {cfg['name']}: Prowler returned no findings — falling back to fixture", "warning")
            else:
                log(f"[AWS] {cfg['name']}: Prowler unavailable ({avail.get('message')}) — using fixture", "warning")
        except Exception as e:
            log(f"[AWS] {cfg['name']}: Prowler call raised {e!r} — using fixture", "error")

    # --- Real-runner path (CloudTrail via boto3 LookupEvents) ---------
    # Same runner serves all three cloudtrail_* sources; the mode flag
    # selects which event-name slice we ask AWS for.
    if source in ('cloudtrail_console', 'cloudtrail_iam', 'cloudtrail_full') and aws_config:
        try:
            from . import cloudtrail_runner
            avail = cloudtrail_runner.is_available(aws_config)
            if avail.get('available'):
                ct_mode = {
                    'cloudtrail_console': 'console_only',
                    'cloudtrail_iam':     'iam_only',
                    'cloudtrail_full':    'full',
                }[source]
                records = cloudtrail_runner.collect_cloudtrail(
                    aws_config,
                    mode=ct_mode,
                    regions=regions,
                    time_filter=time_filter,
                    target_principal_arns=target_principal_arns,
                    log_func=log,
                    is_cancelled_func=is_cancelled_func,
                )
                if records:
                    for r in records:
                        r.setdefault('_source', source)
                        r.setdefault('EventSource', sigma_prefix)
                    log(f"[AWS] {cfg['name']}: {len(records)} live events (CloudTrail)", "info")
                    return records
                log(f"[AWS] {cfg['name']}: 0 live events in window — using fixture as backstop", "info")
            else:
                log(f"[AWS] {cfg['name']}: CloudTrail runner unavailable ({avail.get('message')}) — using fixture", "warning")
        except Exception as e:
            log(f"[AWS] {cfg['name']}: CloudTrail call raised {e!r} — using fixture", "error")

    # --- Real-runner path (GuardDuty findings via boto3) --------------
    if source == 'guardduty_findings' and aws_config:
        try:
            from . import guardduty_runner
            avail = guardduty_runner.is_available(aws_config)
            if avail.get('available'):
                records = guardduty_runner.collect_guardduty(
                    aws_config,
                    regions=regions,
                    log_func=log,
                    is_cancelled_func=is_cancelled_func,
                )
                if records:
                    for r in records:
                        r.setdefault('_source', source)
                        r.setdefault('EventSource', sigma_prefix)
                    log(f"[AWS] {cfg['name']}: {len(records)} live findings (GuardDuty)", "info")
                    return records
                log(f"[AWS] {cfg['name']}: GuardDuty has 0 active findings or no detectors — using fixture as backstop", "info")
            else:
                log(f"[AWS] {cfg['name']}: GuardDuty runner unavailable ({avail.get('message')}) — using fixture", "warning")
        except Exception as e:
            log(f"[AWS] {cfg['name']}: GuardDuty call raised {e!r} — using fixture", "error")

    # --- Real-runner path (Access Analyzer via boto3) -----------------
    if source == 'accessanalyzer_findings' and aws_config:
        try:
            from . import accessanalyzer_runner
            avail = accessanalyzer_runner.is_available(aws_config)
            if avail.get('available'):
                records = accessanalyzer_runner.collect_accessanalyzer(
                    aws_config,
                    regions=regions,
                    log_func=log,
                    is_cancelled_func=is_cancelled_func,
                )
                if records:
                    for r in records:
                        r.setdefault('_source', source)
                        r.setdefault('EventSource', sigma_prefix)
                    log(f"[AWS] {cfg['name']}: {len(records)} live findings (Access Analyzer)", "info")
                    return records
                log(f"[AWS] {cfg['name']}: 0 Access Analyzer findings or no analyzer configured — using fixture as backstop", "info")
            else:
                log(f"[AWS] {cfg['name']}: Access Analyzer runner unavailable ({avail.get('message')}) — using fixture", "warning")
        except Exception as e:
            log(f"[AWS] {cfg['name']}: Access Analyzer call raised {e!r} — using fixture", "error")

    # --- Real-runner path (IAM principals — CloudFox-equivalent) ------
    if source == 'iam_principals' and aws_config:
        try:
            from . import iam_runner
            avail = iam_runner.is_available(aws_config)
            if avail.get('available'):
                records = iam_runner.collect_iam_principals(
                    aws_config,
                    max_principal_age_days=max_principal_age_days,
                    max_access_key_age_days=max_access_key_age_days,
                    target_principal_arns=target_principal_arns,
                    log_func=log,
                    is_cancelled_func=is_cancelled_func,
                )
                if records:
                    for r in records:
                        r.setdefault('_source', source)
                        r.setdefault('EventSource', sigma_prefix)
                    log(f"[AWS] {cfg['name']}: {len(records)} live principals (boto3)", "info")
                    return records
                log(f"[AWS] {cfg['name']}: boto3 enumeration returned no principals — falling back to fixture", "warning")
            else:
                log(f"[AWS] {cfg['name']}: iam_runner unavailable ({avail.get('message')}) — using fixture", "warning")
        except Exception as e:
            log(f"[AWS] {cfg['name']}: iam_runner call raised {e!r} — using fixture", "error")

    # --- Fixture fallback ---------------------------------------------
    fixture = cfg.get('fixture')
    if not fixture:
        return []
    records = _load_fixture(fixture)
    for r in records:
        # Belt-and-suspenders: ensure the shape the SIGMA runner / analyzer
        # expects. Real collectors will do the same.
        r.setdefault('_source', source)
        r.setdefault('EventSource', sigma_prefix)
    log(f"[AWS] {cfg['name']}: {len(records)} records (fixture: {fixture})", "info")
    return records


# =============================================================================
# Main entry point — collect_aws_logs
# =============================================================================


def collect_aws_logs(
    run_id: str,
    aws_config: Dict[str, Any],
    sources: List[str],
    *,
    time_filter: Optional[str] = None,
    regions: Optional[List[str]] = None,
    target_principals: Optional[List[str]] = None,
    scope_mode: str = 'targeted',
    cloudtrail_mode: str = 'light',
    max_principal_age_days: Optional[float] = None,
    max_access_key_age_days: Optional[float] = None,
    log_func: Optional[Callable[[str, str], None]] = None,
) -> Dict[str, List[Dict]]:
    """Collect AWS logs for the requested `sources`.

    Returns a dict keyed by `sigma_prefix` (e.g. `AWS.CloudTrail`) →
    list of records. Same shape `services.azure.collectors.collect_azure_logs`
    returns, so the rest of the pipeline is provider-agnostic.

    In this scaffold every source's collector is a fixture loader. The
    real implementation will call boto3 / Prowler here and keep the same
    return shape.
    """

    def log(msg: str, level: str = "info") -> None:
        if log_func:
            log_func(msg, level)
        if run_id:
            add_log_to_run(run_id, msg, level)

    log(f"[AWS] Collection start — sources={sources}, regions={regions or ['(default)']}, "
        f"scope_mode={scope_mode}, cloudtrail_mode={cloudtrail_mode}", "info")
    if target_principals:
        log(f"[AWS] Targeted principals: {target_principals}", "info")

    # cloudtrail_mode = 'light' downgrades cloudtrail_full to its filtered
    # siblings, matching how the Azure UAL light/full toggle works. This
    # keeps run times sane on real accounts later.
    effective_sources = list(sources)
    if cloudtrail_mode == 'light' and 'cloudtrail_full' in effective_sources:
        effective_sources = [s for s in effective_sources if s != 'cloudtrail_full']
        for s in ('cloudtrail_console', 'cloudtrail_iam'):
            if s not in effective_sources:
                effective_sources.append(s)
        log("[AWS] cloudtrail_mode=light — replaced cloudtrail_full with console+iam slices", "info")

    # If we have a single target principal, pass it as Prowler's
    # --resource-arn for scan-time scoping (Mode 1 in the data-eval doc).
    # The runner only acts on it for source='prowler_posture'.
    resource_arn = None
    if target_principals and len(target_principals) == 1:
        tp = target_principals[0]
        if isinstance(tp, str) and tp.startswith("arn:aws:"):
            resource_arn = tp

    # All target ARNs go to iam_runner so it can do GetUser per-ARN instead
    # of enumerating the entire account.
    target_principal_arns = [
        p for p in (target_principals or [])
        if isinstance(p, str) and p.startswith("arn:aws:")
    ] or None

    def _is_cancelled_for_runner() -> bool:
        return is_cancelled(run_id)

    results: Dict[str, List[Dict]] = {}
    for source in effective_sources:
        if is_cancelled(run_id):
            log("[AWS] Collection cancelled", "warning")
            break
        records = _stub_collect(
            source, log,
            aws_config=aws_config,
            regions=regions,
            resource_arn=resource_arn,
            target_principal_arns=target_principal_arns,
            time_filter=time_filter if isinstance(time_filter, dict) else None,
            is_cancelled_func=_is_cancelled_for_runner,
            max_principal_age_days=max_principal_age_days,
            max_access_key_age_days=max_access_key_age_days,
        )
        if not records:
            continue
        prefix = LOG_SOURCES[source]['sigma_prefix']
        # Multiple sources can share a sigma_prefix (e.g. all CloudTrail
        # slices). Merge under the prefix so downstream SIGMA + analyzer
        # see them grouped — same convention as Azure.
        results.setdefault(prefix, []).extend(records)

    total = sum(len(v) for v in results.values())
    log(f"[AWS] Collection complete — {total} records across {len(results)} sources", "info")
    return results


# =============================================================================
# Offline mode: parse uploaded files
# =============================================================================


def parse_uploaded_logs(
    file_paths: List[str],
    *,
    log_func: Optional[Callable[[str, str], None]] = None,
) -> Dict[str, List[Dict]]:
    """Parse a list of uploaded log files (JSON / JSONL) and group records
    by sigma_prefix, mirroring `services.azure.collectors.parse_uploaded_logs`.

    The auto-detection is keyed by filename (e.g. `cloudtrail*.json` →
    `AWS.CloudTrail`) and by sniffing the first record's shape
    (`EventName` + `EventSource` ⇒ CloudTrail; `Service` + `Severity` ⇒
    GuardDuty; etc.).
    """

    def log(msg: str, level: str = "info") -> None:
        if log_func:
            log_func(msg, level)

    grouped: Dict[str, List[Dict]] = {}
    for path in file_paths:
        if not os.path.exists(path):
            log(f"[AWS] Upload missing: {path}", "warning")
            continue
        try:
            records = _parse_file(path)
        except Exception as ex:
            log(f"[AWS] Failed to parse {path}: {ex}", "warning")
            continue
        if not records:
            continue
        prefix = _detect_prefix_from_filename(os.path.basename(path)) \
            or detect_source_type(records[0]) \
            or 'AWS.Unknown'
        for r in records:
            r.setdefault('EventSource', prefix)
        grouped.setdefault(prefix, []).extend(records)
        log(f"[AWS] Parsed {len(records)} records from {os.path.basename(path)} → {prefix}", "info")
    return grouped


def _parse_file(path: str) -> List[Dict]:
    """Best-effort JSON / JSONL loader. Returns a list of dicts."""
    with open(path, 'r', encoding='utf-8') as f:
        text = f.read().strip()
    if not text:
        return []
    if text.startswith('['):
        data = json.loads(text)
        return data if isinstance(data, list) else []
    if text.startswith('{') and '"Records"' in text[:200]:
        # AWS sometimes wraps trail events in {"Records":[...]}
        data = json.loads(text)
        return data.get('Records', []) if isinstance(data, dict) else []
    # JSONL fallback
    out: List[Dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


_FILENAME_PREFIX_MAP: List[Tuple[str, str]] = [
    ('cloudtrail', 'AWS.CloudTrail'),
    ('guardduty', 'AWS.GuardDuty'),
    ('accessanalyzer', 'AWS.AccessAnalyzer'),
    ('access_analyzer', 'AWS.AccessAnalyzer'),
    ('prowler', 'AWS.Prowler'),
]


def _detect_prefix_from_filename(filename: str) -> Optional[str]:
    lower = filename.lower()
    for needle, prefix in _FILENAME_PREFIX_MAP:
        if needle in lower:
            return prefix
    return None


def detect_source_type(record: Dict) -> Optional[str]:
    """Auto-detect which AWS source a single sample record came from.

    Used by the offline uploader. Looks at the record's distinctive
    fields. Same shape as the Azure version.
    """
    if not isinstance(record, dict):
        return None
    # CloudTrail records have EventName + EventSource (or eventName/eventSource).
    if any(k in record for k in ('EventName', 'eventName')) and any(
        k in record for k in ('EventSource', 'eventSource')
    ):
        return 'AWS.CloudTrail'
    # GuardDuty findings have Service + Severity + Type.
    if 'Service' in record and 'Severity' in record and 'Type' in record:
        return 'AWS.GuardDuty'
    # AccessAnalyzer findings have Resource + ResourceType + Status.
    if 'resourceType' in record and 'status' in record and 'resource' in record:
        return 'AWS.AccessAnalyzer'
    # Prowler OCSF-style findings have check_id + status_code.
    if 'check_id' in record or 'finding_info' in record:
        return 'AWS.Prowler'
    return None
