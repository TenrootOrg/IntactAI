#!/usr/bin/env python3
"""
Generate modules/backend/services/agentic/skills/artifact_map.yaml from the
live Velociraptor artifact catalog.

This is a one-shot offline generator (NOT called at runtime). The output is a
deterministic mapping from artifact name → preferred skill that
`services.agentic.skills.select_skills` consults BEFORE its fuzzy fallback
runs. Re-run this script whenever Velociraptor's artifact set changes
materially (new DetectRaptor artifacts, custom blueprints, new built-ins).

Usage (inside the intact_backend container):
    python3 /app/scripts/generate_skill_map.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import defaultdict
from typing import Dict, List, Tuple

import yaml

# Make services importable when run inside the backend container.
sys.path.insert(0, "/app")

from services.velociraptor_service import setup_velociraptor_connection
from pyvelociraptor import api_pb2, api_pb2_grpc

SKILLS_DIR = "/app/services/agentic/skills"
DFIR_DIR = os.path.join(SKILLS_DIR, "dfir")
OUTPUT_PATH = os.path.join(SKILLS_DIR, "artifact_map.yaml")
MIN_SCORE = 9  # below this, leave artifact unmapped (fuzzy fallback at runtime)

# Strong (topic_in_artifact, topic_in_skill_name, weight) bonuses. Drives the
# bulk of correct mappings — defines the DFIR-domain alignment between
# artifact families and skill families.
TOPIC_BOOSTS: List[Tuple[str, str, int]] = [
    # PowerShell family
    ("powershell",       "powershell",                 9),
    ("psreadline",       "powershell",                 9),
    ("encoded",          "powershell",                 4),
    ("scriptblock",      "powershell",                 6),
    ("powershellmodule", "powershell",                 6),
    # File-system forensic artifacts
    ("lnk",              "lnk-files",                  9),
    ("jumplist",         "lnk-files",                  6),
    ("shortcut",         "lnk-files",                  4),
    ("prefetch",         "prefetch",                   9),
    ("amcache",          "amcache",                    9),
    ("shellbag",         "shellbag",                   9),
    ("recentapp",        "amcache",                    4),  # close cousin
    ("recentdoc",        "shellbag",                   3),
    ("mft",              "mft",                        9),
    ("usn",              "mft",                        5),
    ("ntfs",             "mft",                        4),
    ("recyclebin",       "mft",                        3),
    ("usb",              "usb",                        9),
    ("zoneidentifier",   "browser-history",            3),
    # Persistence-mechanism artifacts
    ("autoruns",         "autoruns",                   9),
    ("autorun",          "autoruns",                   8),
    ("scheduled",        "scheduled-task",             7),
    ("taskschedul",      "scheduled-task",             7),
    ("registry.run",     "registry-run-key",           9),
    ("startup",          "startup-folder",             8),
    ("permanentwmi",     "wmi-persistence",            9),
    ("wmieventconsumer", "wmi-persistence",            9),
    ("wmi",              "wmi",                        7),
    ("services",         "persistence-mechanisms-in-windows", 4),
    ("bootloader",       "rootkit",                    6),
    ("permanentwmi",     "lateral-movement-via-wmi",   5),
    # Process / memory analysis
    ("malfind",          "process-injection",          9),
    ("inject",           "process-injection",          9),
    ("hollow",           "process-hollowing",          9),
    ("pslist",           "process-injection",          3),
    ("pstree",           "process-hollowing",          4),
    ("hijacklib",        "dll-sideloading",            9),
    ("sideload",         "dll-sideloading",            9),
    ("loldriver",        "dll-sideloading",            5),
    ("untrustedbinary",  "dll-sideloading",            5),
    ("binaryrename",     "evasion-techniques",         6),
    ("memory",           "memory-forensics",           7),
    ("memorydump",       "credentials-from-memory",    7),
    # Detection / hunting
    ("yara",             "yara",                       9),
    ("yararule",         "yara",                       9),
    ("sigma",            "yara",                       4),
    ("hayabusa",         "evasion-techniques",         3),
    # Event-log + audit
    ("evtx",             "event-logs",                 8),
    ("eventlog",         "event-logs",                 8),
    ("audit",            "linux-audit",                7),
    # Browser / app history
    ("browser",          "browser-history",            8),
    ("chrome",           "browser-history",            8),
    ("edge",             "browser-history",            8),
    ("firefox",          "browser-history",            8),
    ("webhistory",       "browser-history",            8),
    ("hindsight",        "browser-history",            6),
    # Network artifacts
    ("netstat",          "network-traffic",            7),
    ("arpcache",         "network-traffic",            5),
    ("dnscache",         "command-and-control",        4),
    ("dns",              "dns-based",                  4),
    # Credential / AD attacks — bumped to 15 so specific-topic skills
    # outscore generic event-log aggregators when both could apply.
    ("kerber",           "kerberoast",                 15),
    ("ntlm",             "ntlm-relay",                 15),
    ("dcsync",           "dcsync",                     15),
    ("goldenticket",     "golden-ticket",              15),
    ("mimikatz",         "mimikatz",                   15),
    ("rdpauth",          "pass-the-hash",              7),
    ("rdpclient",        "pass-the-hash",              7),
    (".sam",             "pass-the-hash",              12),  # narrow ".SAM" to avoid false hits
    # Malware analysis
    ("rootkit",          "rootkit",                    9),
    ("packed",           "packed-malware",             8),
    ("upx",              "packed-malware",             5),
    ("macro",            "macro-malware",              8),
    ("officedoc",        "macro-malware",              5),
    ("cobalt",           "cobalt-strike",              9),
    ("beacon",           "cobalt-strike",              7),
    # Email
    ("email",            "email-headers",              7),
    ("outlook",          "email-headers",              6),
    ("pst",              "email-headers",              5),
    # Linux — patterns aligned with actual Velociraptor artifact names
    # (Linux.Persistence.*, Linux.Forensics.*, Linux.Collection.*,
    # Linux.Sigma.*, Linux.Detection.*, Linux.Memory.*, Linux.Network.*,
    # Linux.Carving.SSHLogs, Linux.LogAnalysis.*).
    ("linux.persistence","persistence-mechanisms-in-linux", 15),
    ("ldpreload",        "persistence-mechanisms-in-linux", 12),
    ("linux.forensics",  "linux-system-artifacts",     10),
    ("linux.collection", "linux-system-artifacts",     10),
    ("linux.detection",  "linux-system-artifacts",      8),
    ("linux.sigma",      "linux-system-artifacts",      6),
    ("linux.memory",     "memory-forensics-with-volatility3", 12),
    ("linux.network",    "network-traffic-for-incidents", 10),
    ("linux.carving.ssh","linux-audit-logs",           10),
    ("linux.loganalysis","linux-log-forensics",        12),
    ("linux.applications.docker", "linux-system-artifacts", 6),
    ("linux.elf",        "linux-elf-malware",          15),
    ("rootkit",          "linux-kernel-rootkits",      12),  # Linux-flavored
    ("kernel",           "linux-kernel-rootkits",       8),
    ("audit",            "linux-audit-logs",           10),
    ("auth.log",         "linux-audit-logs",           10),
    ("syslog",           "linux-log-forensics",         8),
    # Generic / fallback
    ("ransomware",       "ransomware-encryption",      6),
    ("shadowcopy",       "shadow-copy",                9),
    ("vss",              "shadow-copy",                7),
]


def tokenize(name: str) -> List[str]:
    """Tokenize a dotted CamelCase name into lowercase word tokens."""
    if not name:
        return []
    parts = re.split(r"[.\s/_-]+", name)
    out = []
    for p in parts:
        for sub in re.findall(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|\d+", p):
            t = sub.lower()
            if t and t not in _STOPLIST:
                out.append(t)
    seen = set()
    return [t for t in out if not (t in seen or seen.add(t))]


# Words that don't carry topic signal — either skill-name templates
# ("analyzing", "performing") or English connectors / Velociraptor type
# prefixes. Kept domain-meaningful words like windows / linux / log /
# registry / file because they DO discriminate.
_STOPLIST = {
    # English connectors
    "for", "with", "the", "and", "of", "to", "in", "on", "by", "from",
    "is", "as", "an", "a", "or",
    # Skill-name template verbs (appear in most skill names, no signal)
    "analyzing", "performing", "investigating", "detecting", "hunting",
    "extracting", "collecting", "deobfuscating", "investigation",
    # Velociraptor artifact-tree top-levels (every artifact has one)
    "client", "server", "custom", "generic", "exchange",
    # Too-common shared nouns (in 100s of artifact names AND many skill
    # names, so contribute pure noise to overlap counting). OS alignment
    # is handled by a dedicated penalty, so dropping "windows"/"linux"
    # here does not break OS-aware matching.
    "windows", "linux", "macos",
    "files", "artifacts", "system", "data", "info",
    "user", "users", "process", "processes",
}


def _load_skills() -> Dict[str, dict]:
    """Read skill frontmatter directly off disk (avoids importing the
    backend's services.agentic which has side effects).
    """
    skills: Dict[str, dict] = {}
    if not os.path.isdir(DFIR_DIR):
        print(f"ERROR: skills dir not found: {DFIR_DIR}", file=sys.stderr)
        sys.exit(2)
    for fname in os.listdir(DFIR_DIR):
        if not fname.endswith(".md"):
            continue
        path = os.path.join(DFIR_DIR, fname)
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
        if not text.startswith("---"):
            continue
        parts = text.split("---", 2)
        if len(parts) < 3:
            continue
        try:
            meta = yaml.safe_load(parts[1]) or {}
        except yaml.YAMLError:
            continue
        name = meta.get("name") or fname[:-3]
        skills[name] = {
            "name": name,
            "tags": [str(t).lower() for t in (meta.get("tags") or [])],
            "description": (meta.get("description") or "").lower(),
        }
    return skills


def score(artifact: dict, skill: dict) -> int:
    """Score how well a skill fits an artifact. Higher is better."""
    art_name = artifact.get("name", "")
    art_name_lc = art_name.lower()
    art_desc_lc = (artifact.get("description") or "").lower()
    skill_name = skill["name"]
    skill_name_lc = skill_name.lower()

    art_tokens = tokenize(art_name)
    art_desc_words = set(re.findall(r"[a-z][a-z0-9]+", art_desc_lc))
    skill_tokens = tokenize(skill_name)
    skill_tag_words = {w for t in skill["tags"] for w in re.split(r"[\s\-_]+", t) if w}
    skill_desc_words = set(re.findall(r"[a-z][a-z0-9]+", skill["description"]))

    s = 0
    # Token overlap between artifact name and skill name (direct topic match).
    s += 5 * len(set(art_tokens) & set(skill_tokens))
    # Artifact name tokens found in skill tags.
    s += 3 * len(set(art_tokens) & skill_tag_words)
    # Artifact description words found in skill name tokens.
    s += 2 * len(art_desc_words & set(skill_tokens))
    # Artifact description words found in skill tags.
    s += 1 * len(art_desc_words & skill_tag_words)

    # Topic boosts: substring co-occurrence of named topics across both sides.
    for art_pat, skill_pat, weight in TOPIC_BOOSTS:
        if art_pat in art_name_lc and skill_pat in skill_name_lc:
            s += weight
        # Also a smaller bonus if the topic appears in the artifact description
        # (so e.g. an artifact whose name doesn't say "powershell" but whose
        # description does still attracts the powershell skill).
        elif art_pat in art_desc_lc and skill_pat in skill_name_lc:
            s += max(2, weight // 3)

    # OS / domain alignment penalty for cross-platform mismatches.
    if "linux" in art_name_lc and "linux" not in skill_name_lc:
        s -= 4
    if "linux" not in art_name_lc and "linux" in skill_name_lc:
        s -= 4

    return s


def main() -> int:
    skills = _load_skills()
    print(f"loaded {len(skills)} skills from {DFIR_DIR}", file=sys.stderr)

    ch = setup_velociraptor_connection()
    if not ch:
        print("ERROR: cannot connect to Velociraptor", file=sys.stderr)
        return 2

    stub = api_pb2_grpc.APIStub(ch)
    req = api_pb2.VQLCollectorArgs(
        max_wait=30, max_row=2000,
        Query=[api_pb2.VQLRequest(VQL="SELECT name, description, type FROM artifact_definitions()")],
    )

    artifacts: List[dict] = []
    for resp in stub.Query(req, timeout=120):
        if resp.Response:
            for row in json.loads(resp.Response):
                artifacts.append(row)
    print(f"fetched {len(artifacts)} artifact definitions from Velociraptor", file=sys.stderr)

    # Filter to client-type artifacts (server / internal artifacts produce
    # results the agent doesn't analyze).
    client_artifacts = [a for a in artifacts if a.get("type") == "client"]
    print(f"client-type only: {len(client_artifacts)}", file=sys.stderr)

    # Score every (artifact, skill) pair and pick top-1 per artifact.
    mapped: Dict[str, str] = {}
    unmapped: List[str] = []
    by_skill: Dict[str, int] = defaultdict(int)
    for a in client_artifacts:
        name = a.get("name", "")
        if not name:
            continue
        scored = [(score(a, s), s["name"]) for s in skills.values()]
        scored.sort(key=lambda x: -x[0])
        best_score, best_skill = scored[0] if scored else (0, "")
        if best_score >= MIN_SCORE:
            mapped[name] = best_skill
            by_skill[best_skill] += 1
        else:
            unmapped.append(name)

    print(file=sys.stderr)
    print(f"mapped:   {len(mapped)} / {len(client_artifacts)}", file=sys.stderr)
    print(f"unmapped: {len(unmapped)} (will fall back to runtime fuzzy match)", file=sys.stderr)
    print(file=sys.stderr)
    print("=== top 15 most-used skills in the map ===", file=sys.stderr)
    for sk, n in sorted(by_skill.items(), key=lambda x: -x[1])[:15]:
        print(f"  {n:>3}  {sk}", file=sys.stderr)

    # Emit YAML, grouped by top-level artifact category for readability.
    grouped: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
    for art_name, skill_name in mapped.items():
        category = ".".join(art_name.split(".", 2)[:2]) or "Misc"
        grouped[category].append((art_name, skill_name))

    out_lines: List[str] = [
        "# artifact_map.yaml — generated by scripts/generate_skill_map.py",
        "# DO NOT hand-edit this file; re-run the generator to regenerate.",
        "# Hand-tuned overrides go in artifact_map_overrides.yaml (loaded after this).",
        f"# Generated: {len(mapped)} mapped, {len(unmapped)} unmapped",
        "#",
        "# Format:",
        "#   exact:   <Velociraptor artifact name>: <skill name>",
        "#   patterns: list of {pattern: <glob>, skill: <name>}  (checked AFTER exact)",
        "#",
        "# Selector consults this map BEFORE the runtime fuzzy match.",
        "# Unmapped artifacts fall through to fuzzy match in skills.py.",
        "",
        "exact:",
    ]
    for category in sorted(grouped.keys()):
        out_lines.append(f"  # --- {category} ---")
        for art_name, skill_name in sorted(grouped[category]):
            # Quote keys that contain special chars; YAML safety.
            out_lines.append(f"  \"{art_name}\": {skill_name}")
        out_lines.append("")

    out_lines.extend([
        "patterns: []   # add hand-tuned glob overrides here, e.g.",
        "               # - { pattern: 'Custom.Windows.Forensics.*', skill: performing-malware-persistence-investigation }",
        "",
    ])

    # Write atomically.
    tmp_path = OUTPUT_PATH + ".tmp"
    with open(tmp_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out_lines))
    os.replace(tmp_path, OUTPUT_PATH)
    print(f"\nwrote {OUTPUT_PATH}", file=sys.stderr)

    # Sanity: does it parse?
    with open(OUTPUT_PATH) as f:
        parsed = yaml.safe_load(f)
    assert isinstance(parsed.get("exact"), dict), "YAML output is malformed"
    print(f"YAML round-trip OK ({len(parsed['exact'])} exact entries)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
