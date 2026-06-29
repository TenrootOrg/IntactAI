#!/usr/bin/env python3
"""
DFIR macro-skill loader/selector for the fusion analyst.

A "macro skill" is a markdown file (YAML frontmatter + body) describing a
cross-artifact DFIR investigation playbook. Fusion's analyst pass (real-LLM
mode) picks ONE macro for the whole case and injects its body into the system
prompt.

The macros ship as STATIC files under services/agentic/skills/macros/ — there
is NO runtime download.

(The old PER-ARTIFACT skill system — select_skills + the dfir/ corpus + the
artifact_map + the GitHub skills_download_service + the maintenance "refresh
skills" task — was removed: the agentic per-artifact LLM analysis it fed no
longer exists. Only the cross-artifact macro path that fusion uses remains.)
"""

import logging
import os
import re
from typing import Dict, List, Optional

import yaml

from services.agentic.constants import (
    SKILL_BODY_HARD_CAP,
    SKILL_BODY_SOFT_CAP,
    SKILL_MIN_SCORE,
    LOG_PREFIX_SKILLS,
)

logger = logging.getLogger(__name__)

# Single in-memory index of macro playbooks, populated once at boot from the
# bundled static corpus. Threads share it read-only.
_MACRO_INDEX: Dict[str, dict] = {}
_SKILLS_LOADED = False

# Macros ship statically with the code (read-only inside the container). No
# writable cache, no download — just these files.
_MACROS_DIR = os.path.join(os.path.dirname(__file__), "skills", "macros")


def _approx_tokens(text: str) -> int:
    """Rough char/4 token estimate. Good enough for size gating."""
    return len(text) // 4


def _parse_skill_file(path: str) -> Optional[dict]:
    """Parse a SKILL markdown file with YAML frontmatter. Returns dict with
    frontmatter fields + 'body' + '_path', or None if malformed."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except OSError as e:
        logger.warning("%s could not read %s: %s", LOG_PREFIX_SKILLS, path, e)
        return None

    if not text.startswith("---"):
        logger.warning("%s missing frontmatter: %s", LOG_PREFIX_SKILLS, path)
        return None
    parts = text.split("---", 2)
    if len(parts) < 3:
        logger.warning("%s malformed frontmatter: %s", LOG_PREFIX_SKILLS, path)
        return None
    try:
        meta = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError as e:
        logger.warning("%s YAML parse error in %s: %s", LOG_PREFIX_SKILLS, path, e)
        return None
    if not isinstance(meta, dict) or not meta.get("name"):
        logger.warning("%s missing 'name' in frontmatter: %s", LOG_PREFIX_SKILLS, path)
        return None

    body = parts[2].lstrip("\n")
    body_tokens = _approx_tokens(body)
    if body_tokens > SKILL_BODY_HARD_CAP:
        logger.warning("%s body too large (%d tok > %d hard cap), skipping: %s",
                       LOG_PREFIX_SKILLS, body_tokens, SKILL_BODY_HARD_CAP, path)
        return None
    if body_tokens > SKILL_BODY_SOFT_CAP:
        logger.info("%s body large (%d tok > %d soft cap): %s",
                    LOG_PREFIX_SKILLS, body_tokens, SKILL_BODY_SOFT_CAP, path)

    meta["body"] = body
    meta["_path"] = path
    meta["_body_tokens"] = body_tokens
    return meta


def load_macro_index_at_boot() -> Dict[str, dict]:
    """Load the static macro corpus once (idempotent). Called from
    agentic/__init__.py at import."""
    global _SKILLS_LOADED
    if _SKILLS_LOADED:
        return _MACRO_INDEX
    if not os.path.isdir(_MACROS_DIR):
        logger.info("%s no macros dir at %s — macro skills disabled", LOG_PREFIX_SKILLS, _MACROS_DIR)
        _SKILLS_LOADED = True
        return _MACRO_INDEX

    loaded = skipped = 0
    for fname in sorted(os.listdir(_MACROS_DIR)):
        if not fname.endswith(".md") or fname in ("README.md", "INDEX.md", "NOTICE.md", "LICENSING.md"):
            continue
        meta = _parse_skill_file(os.path.join(_MACROS_DIR, fname))
        if meta is None:
            skipped += 1
            continue
        name = meta["name"]
        if name in _MACRO_INDEX:
            logger.warning("%s duplicate macro %r — keeping first", LOG_PREFIX_SKILLS, name)
            skipped += 1
            continue
        _MACRO_INDEX[name] = meta
        loaded += 1
    logger.info("%s loaded %d macro skills from %s (%d skipped)",
                LOG_PREFIX_SKILLS, loaded, _MACROS_DIR, skipped)
    _SKILLS_LOADED = True
    return _MACRO_INDEX


# Back-compat name for the boot caller in agentic/__init__.py.
load_skill_index_at_boot = load_macro_index_at_boot


# ---------------------------------------------------------------------------
# Scoring helpers (macro selection)
# ---------------------------------------------------------------------------

def _tokenize_artifact(name: str) -> List[str]:
    """Split a Velociraptor artifact name into lowercased keyword tokens."""
    if not name:
        return []
    tokens = []
    for p in re.split(r"[.\s/_-]+", name):
        for sub in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", p):
            tokens.append(sub.lower())
    seen = set()
    return [t for t in tokens if not (t in seen or seen.add(t))]


_MITRE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)


def _extract_mitre_ids(skill: dict) -> set:
    """Pull canonical-cased MITRE technique IDs from a skill's frontmatter
    (`mitre_attack:` or `tags:`)."""
    out: set = set()
    for source_key in ("mitre_attack", "tags"):
        vals = skill.get(source_key) or []
        if not isinstance(vals, list):
            continue
        for x in vals:
            s = str(x).strip()
            if _MITRE_ID_RE.fullmatch(s):
                out.add(s.upper())
    return out


def _count_mitre_matches(skill_ids: set, query_ids: List[str]) -> int:
    """Count query technique IDs matching the skill, exact or parent-fallback."""
    matched = 0
    for q in query_ids:
        q_up = str(q).strip().upper()
        if q_up in skill_ids or q_up.split(".", 1)[0] in skill_ids:
            matched += 1
    return matched


def _score_skill(skill: dict, artifact_tokens: List[str], mitre_ids: List[str]) -> int:
    """Score a macro against the aggregated case context:
      +5 per matching MITRE technique ID (parent-fallback)
      +2 per matching tag word against context tokens
      +1 per context token found in the description"""
    score = 0
    if mitre_ids:
        skill_mitre = _extract_mitre_ids(skill)
        if skill_mitre:
            score += 5 * _count_mitre_matches(skill_mitre, mitre_ids)

    tags = skill.get("tags") or []
    if isinstance(tags, list) and artifact_tokens:
        tag_words: set = set()
        for t in tags:
            s = str(t).strip()
            if _MITRE_ID_RE.fullmatch(s):
                continue
            for w in re.split(r"[\s\-_]+", s.lower()):
                if w:
                    tag_words.add(w)
        score += 2 * len(set(artifact_tokens) & tag_words)

    desc = (skill.get("description") or "").lower()
    if desc and artifact_tokens:
        score += sum(1 for t in artifact_tokens if t in desc)
    return score


# ---------------------------------------------------------------------------
# Public API (used by services/fusion/llm_sim.py)
# ---------------------------------------------------------------------------

def compose_system_prompt(base_prompt: str, skill_names: List[str]) -> str:
    """Append the bodies of `skill_names` (macro names) to `base_prompt`. If
    none resolve, `base_prompt` is returned unchanged."""
    if not skill_names:
        return base_prompt
    bodies = []
    for name in skill_names:
        macro = _MACRO_INDEX.get(name)
        body = macro.get("body", "") if macro else ""
        if body:
            bodies.append(f"<!-- skill: {name} -->\n{body.strip()}")
    if not bodies:
        return base_prompt
    return (base_prompt + "\n\n## DOMAIN KNOWLEDGE (skill cards)\n\n"
            + "\n\n---\n\n".join(bodies))


def select_macro_skill(
    aggregated_mitre: Optional[List[str]] = None,
    severity_counts: Optional[Dict[str, int]] = None,
    artifact_names: Optional[List[str]] = None,
    exclude: Optional[set] = None,
) -> Optional[str]:
    """Pick the single best macro playbook for the case-level analyst pass.

    Inputs are the cross-artifact aggregate (MITRE IDs, severity distribution,
    artifact names). Returns the macro name to inject, or None if the index is
    empty / nothing clears SKILL_MIN_SCORE.
    """
    if not _MACRO_INDEX:
        return None

    aggregated_mitre = list(aggregated_mitre or [])
    severity_counts = dict(severity_counts or {})
    artifact_names = list(artifact_names or [])
    exclude = set(exclude or ())

    # Hard-pin: predominantly Azure / Entra cloud-IR runs prefer the cloud macro
    # over any endpoint-forensics one the fuzzy scorer might pick.
    azure_macro = "intact-investigating-azure-account-compromise"
    if azure_macro in _MACRO_INDEX and azure_macro not in exclude and artifact_names:
        azure_shaped = sum(
            1 for a in artifact_names
            if a.startswith(("Azure.", "UAL.", "INV.", "SIGMA.Azure_", "SIGMA.Sign-ins",
                             "SIGMA.Sign_ins", "SIGMA.Application_", "SIGMA.Service_Principal",
                             "SIGMA.OAuth_", "SIGMA.Consent_", "SIGMA.Conditional_Access",
                             "SIGMA.Federation", "SIGMA.MFA_", "SIGMA.Added_"))
        )
        if azure_shaped >= max(1, len(artifact_names) // 2):
            return azure_macro

    context_tokens: List[str] = []
    for art in artifact_names:
        context_tokens.extend(_tokenize_artifact(art))
    if severity_counts.get("critical", 0) >= 1:
        context_tokens.extend(["incident", "ransomware", "breach"])
    if severity_counts.get("high", 0) >= 3:
        context_tokens.extend(["malware", "investigation"])
    seen = set()
    context_tokens = [t for t in context_tokens if not (t in seen or seen.add(t))]

    scored = []
    for name, macro in _MACRO_INDEX.items():
        if name in exclude:
            continue
        s = _score_skill(macro, context_tokens, aggregated_mitre)
        if s >= SKILL_MIN_SCORE:
            scored.append((s, name))

    if not scored:
        # Fallback to the broadest endpoint playbook when there's real severity.
        if severity_counts.get("critical", 0) + severity_counts.get("high", 0) >= 1:
            for fallback in ("performing-endpoint-forensics-investigation",
                             "performing-malware-triage-with-yara",
                             "conducting-malware-incident-response"):
                if fallback in _MACRO_INDEX and fallback not in exclude:
                    return fallback
        return None

    scored.sort(key=lambda x: (-x[0], x[1]))
    return scored[0][1]
