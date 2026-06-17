"""Unified severity — one 5-level scale across every module.

Modules speak different dialects: memory emits a numeric anomaly score
(services/memory/analyzers.py:_row_severity — RWX x100, LOLBins x10,
network x1), agentic/SIGMA emit strings (informational..critical), CVE
emits CVSS floats. This collapses all of them to ONE ordered scale so a
case-wide ``min_severity`` filter and ranking are coherent.
"""

from __future__ import annotations

LEVELS = ("informational", "low", "medium", "high", "critical")
_RANK = {lvl: i for i, lvl in enumerate(LEVELS)}


def rank(level: str) -> int:
    return _RANK.get((level or "informational").strip().lower(), 0)


def at_least(level: str, floor: str) -> bool:
    return rank(level) >= rank(floor)


def from_anomaly(score: int) -> str:
    """Map the memory/_row_severity numeric IOC score to a level.

    >=100 = RWX/injected memory (critical-ish), >=10 = LOLBin/suspicious
    path (high), >=1 = live network (low), 0 = benign baseline.
    """
    if score >= 100:
        return "critical"
    if score >= 20:
        return "high"
    if score >= 10:
        return "medium"
    if score >= 1:
        return "low"
    return "informational"


def from_cvss(score) -> str:
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "informational"
    if s >= 9.0:
        return "critical"
    if s >= 7.0:
        return "high"
    if s >= 4.0:
        return "medium"
    if s > 0:
        return "low"
    return "informational"


def from_string(level) -> str:
    """Normalise an arbitrary module/SIGMA severity string to a LEVEL."""
    s = (str(level) if level is not None else "").strip().lower()
    if s in _RANK:
        return s
    alias = {
        "info": "informational", "informational": "informational",
        "warning": "medium", "warn": "medium", "moderate": "medium",
        "error": "high", "severe": "high", "important": "high",
        "crit": "critical", "emergency": "critical", "alert": "critical",
        "none": "informational", "unknown": "informational",
    }
    return alias.get(s, "informational")


def max_level(*levels: str) -> str:
    best = "informational"
    for lv in levels:
        if rank(lv) > rank(best):
            best = lv
    return best
