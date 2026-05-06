"""
Microsoft Azure-Sentinel rules loader for the Intact Azure pipeline.

The public Azure-Sentinel repo (https://github.com/Azure/Azure-Sentinel) ships
hundreds of detection rules and hunting queries written for Microsoft's
Sentinel SaaS. The MIT license lets us harvest the rule logic and run it
through our own Sigma engine.

This module loads those rule YAMLs from a host-side directory the operator
populated manually (per Round 3 install instructions — no install.sh
auto-pull yet) and tags each rule with `_intact_rule_kind` so the SIGMA
matcher can filter sensibly:

  - point_event:  matches a single observable event. Useful in BOTH
                  targeted and tenant-wide scans.
  - aggregate:    needs threshold counts (e.g. ">= 10 failures from
                  >= 3 IPs in 1h"). Targeted scans never carry enough data
                  to trigger these — skip them in targeted mode.
  - baseline:     needs historical context ("first time from country X",
                  "rare app consent"). Tenant-wide-only.

The classifier is a heuristic over the rule's text (description, query,
selection clauses); KQL- and Sigma-format rules both work because we look
for the same vocabulary.

Generic by design: works for any future rule the operator adds, no
hand-curated allowlist of "interesting" rule names.
"""

import os
import re
from typing import Dict, List, Optional


# Where the operator drops the cloned Sentinel rules. Manual rsync per the
# Round 3 README. Host: /home/tenroot/intact/data/sentinel-rules/, mounted
# into the container at /app/data/sentinel-rules/.
SENTINEL_RULES_DIR = os.getenv(
    'INTACT_SENTINEL_RULES_DIR',
    '/app/data/sentinel-rules',
)


# Heuristic vocabularies. Order matters: aggregate is checked before
# baseline because some rules are both (count >= N AND first-time-seen);
# we treat those as aggregate (the count threshold dominates targeted-mode
# eligibility).

# Matches KQL/Sigma idioms for "count of N or more events"
_AGGREGATE_PATTERNS = (
    re.compile(r'\bcount\s*\(\s*\)\s*[><=]+\s*\d+', re.IGNORECASE),
    re.compile(r'\bcount\b\s*(by|>=|>)\s*', re.IGNORECASE),
    re.compile(r'\bdistinct\s*[\w_]+\s*[><=]+\s*\d+', re.IGNORECASE),
    re.compile(r'\bsummarize\b.*\bcount\(\)', re.IGNORECASE),
    re.compile(r'\bdcount\s*\(', re.IGNORECASE),
    re.compile(r'\b>\s*\d+\s+(distinct|unique)\b', re.IGNORECASE),
    re.compile(r'\b(within|over)\s+\d+\s*(min|hour|day)', re.IGNORECASE),
    re.compile(r'\bthreshold\b', re.IGNORECASE),
    re.compile(r'\| count\b', re.IGNORECASE),  # Sigma `condition: ... | count()`
)

# Matches "first time / rare / unusual / never seen" idioms
_BASELINE_PATTERNS = (
    re.compile(r'\bfirst\s+time\b', re.IGNORECASE),
    re.compile(r'\bnever\s+seen\b', re.IGNORECASE),
    re.compile(r'\brarely?\s+(seen|used)\b', re.IGNORECASE),
    re.compile(r'\banomalous\b', re.IGNORECASE),
    re.compile(r'\bunusual\b', re.IGNORECASE),
    re.compile(r'\bdeviat(es?|ion)\b', re.IGNORECASE),
    re.compile(r'\bnot\s+previously\s+seen\b', re.IGNORECASE),
    re.compile(r'\bnew\s+(country|location|ip|user|device)', re.IGNORECASE),
)


def classify_rule_kind(rule: Dict) -> str:
    """Return 'aggregate' | 'baseline' | 'point_event' for a rule.

    Walks the rule's textual surface (name, description, query, detection
    selections) looking for aggregation thresholds or baseline-deviation
    vocabulary. Default is `point_event` — the safe assumption that lets
    a rule match a single observable event.
    """
    if not isinstance(rule, dict):
        return 'point_event'

    # Concatenate all the textual fields a rule typically has
    blobs: List[str] = []
    for key in ('name', 'description', 'query', 'queryFrequency',
                'queryPeriod', 'triggerThreshold', 'eventGroupingSettings'):
        v = rule.get(key)
        if isinstance(v, str):
            blobs.append(v)
    # Sigma-style rules carry a `detection:` block; serialise it to a string
    detection = rule.get('detection')
    if isinstance(detection, (dict, list)):
        blobs.append(repr(detection))

    haystack = '\n'.join(blobs)

    if any(p.search(haystack) for p in _AGGREGATE_PATTERNS):
        return 'aggregate'
    if any(p.search(haystack) for p in _BASELINE_PATTERNS):
        return 'baseline'
    return 'point_event'


def load_sentinel_rules(rule_dir: Optional[str] = None) -> List[Dict]:
    """Load Sentinel rule YAMLs from the manual-install directory.

    Returns a list of rule dicts, each tagged with `_intact_rule_kind`
    and `_intact_source: "sentinel"` so downstream filtering and logging
    can distinguish them from the SigmaHQ corpus.

    Returns [] (with a clear info log) when the directory is empty or
    missing — the operator hasn't done the manual install yet, which is
    expected in fresh deployments.

    Sigma-format rules pass through unchanged (the SIGMA matcher consumes
    them directly). KQL-only rules are dropped in this first cut — they
    need a KQL→Sigma conversion that's tracked as a Round 3 follow-up.
    Each rule's existing fields are preserved; we only add `_intact_*`
    keys so we never collide with rule semantics.
    """
    if rule_dir is None:
        rule_dir = SENTINEL_RULES_DIR

    if not os.path.isdir(rule_dir):
        # Not an error — operator may not have done the manual install
        print(
            f"[SENTINEL] Rules directory not found: {rule_dir} "
            f"(this is expected if Round 3 manual install hasn't been run)",
            flush=True,
        )
        return []

    try:
        import yaml
    except ImportError:
        print("[SENTINEL] PyYAML not available; skipping Sentinel rules", flush=True)
        return []

    loaded = []
    skipped_kql_only = 0
    skipped_parse_err = 0

    for root, _, files in os.walk(rule_dir):
        for filename in files:
            if not filename.endswith(('.yml', '.yaml')):
                continue
            path = os.path.join(root, filename)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
            except Exception as ex:
                skipped_parse_err += 1
                print(f"[SENTINEL] Parse failed: {path}: {ex}", flush=True)
                continue
            if not isinstance(rule, dict):
                continue

            # Skip KQL-only rules in this first cut (Sigma-format rules have
            # a `detection:` block; KQL-only rules just have `query:`). The
            # KQL path is a separate follow-up.
            if 'detection' not in rule and 'query' in rule:
                skipped_kql_only += 1
                continue

            rule['_file_path'] = path
            rule['_file_name'] = filename
            rule['_intact_source'] = 'sentinel'
            rule['_intact_rule_kind'] = classify_rule_kind(rule)
            loaded.append(rule)

    # Per-kind tally so the operator sees the shape of what got loaded
    kinds = {}
    for r in loaded:
        k = r.get('_intact_rule_kind', 'point_event')
        kinds[k] = kinds.get(k, 0) + 1
    kinds_str = ', '.join(f"{v} {k}" for k, v in sorted(kinds.items()))

    print(
        f"[SENTINEL] Loaded {len(loaded)} rules from {rule_dir} "
        f"({kinds_str}; skipped {skipped_kql_only} KQL-only, "
        f"{skipped_parse_err} parse failures)",
        flush=True,
    )
    return loaded
