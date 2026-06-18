"""Calibration harness — score the fusion findings against ground-truth labels
on the committed real purple-team fixtures (clean + attack), and sweep thresholds.

This is the feedback loop that turns hardcoded thresholds (anomaly cutoffs, SIGMA
min-severity, coordinated-activity min-rules/tactics) from guesses into values tuned
to a measurable target: **recognize the simulated attack with zero false positives on
the clean box.** Finding-level precision/recall (the FP we chase is a spurious finding).

Run inside the backend container:
    python3 -m services.fusion.calibrate            # prints per-fixture P/R/F1
"""

from __future__ import annotations

import json
import os

from . import correlate, severity as sev
from .mappers import map_agentic

FIX_DIR = os.path.join(os.path.dirname(__file__), "tests", "fixtures")


def load_fixture(name: str) -> dict:
    with open(os.path.join(FIX_DIR, f"{name}.json")) as f:
        return json.load(f)


def load_labels() -> dict:
    with open(os.path.join(FIX_DIR, "labels.json")) as f:
        return json.load(f)


def _contribution(fx: dict):
    return map_agentic(fx["collected_data"], run_id=fx["run_id"],
                       hostnames={fx["client_id"]: fx["hostname"]})


def build_baseline(name: str) -> dict:
    """A per-environment fingerprint of 'normal' from a clean fixture: the set of
    SIGMA detection titles + finding titles + suspicious service binary paths that
    fired with no attack present. Set-membership, no index needed."""
    g = fuse(name)
    sigma_titles = {e.attrs.get("title") or e.label
                    for e in g.by_type("event") if "sigma" in e.flags}
    finding_titles = {f.title.split(" on ")[0] for f in g.findings}
    svc_paths = {(e.attrs.get("binary") or "").lower()
                 for e in g.by_type("service") if e.attrs.get("binary")}
    return {"sigma_titles": sorted(t for t in sigma_titles if t),
            "finding_titles": sorted(finding_titles),
            "service_paths": sorted(p for p in svc_paths if p),
            "host_role": g.entities and next(iter(g.by_type("asset")), None)
            and next(iter(g.by_type("asset"))).label or "?"}


def fuse(name: str, *, baseline=None, window=None):
    """Fuse a fixture into a graph. Passes baseline/window through to assemble if
    that build supports them (forward-compatible: pre-Phase-3 assemble ignores them
    via the TypeError fallback, so this harness runs on every phase)."""
    fx = load_fixture(name)
    contrib = _contribution(fx)
    try:
        return correlate.assemble(name, [contrib], [fx["run_id"]],
                                  baseline=baseline, window=window)
    except TypeError:
        return correlate.assemble(name, [contrib], [fx["run_id"]])


def _matches(finding, spec) -> bool:
    if spec.get("title_contains", "").lower() not in finding.title.lower():
        return False
    floor = spec.get("min_severity")
    return (not floor) or sev.at_least(finding.severity, floor)


def score(graph, label: dict) -> dict:
    """Finding-level precision/recall against a label.
    - recall: fraction of expected_findings present.
    - FP sources: any finding matching must_not_fire_titles, OR (when
      expected is empty) any finding >= must_not_fire_min_severity."""
    findings = list(graph.findings)
    expected = label.get("expected_findings") or []
    tp = sum(1 for spec in expected if any(_matches(f, spec) for f in findings))
    fn = len(expected) - tp

    fp = 0
    bad_titles = [t.lower() for t in (label.get("must_not_fire_titles") or [])]
    floor = label.get("must_not_fire_min_severity")
    for f in findings:
        if any(b in f.title.lower() for b in bad_titles):
            fp += 1
        elif floor and not expected and sev.at_least(f.severity, floor):
            fp += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 3),
            "recall": round(recall, 3), "f1": round(f1, 3),
            "n_findings": len(findings)}


def evaluate(verbose=True) -> dict:
    """Score every labeled fixture, using each fixture's named baseline + window."""
    labels = load_labels()
    out = {}
    for name, label in labels.items():
        if name.startswith("_"):
            continue
        baseline = build_baseline(label["baseline"]) if label.get("baseline") else None
        g = fuse(name, baseline=baseline, window=label.get("window"))
        out[name] = score(g, label)
        if verbose:
            s = out[name]
            print(f"{name:8} P={s['precision']} R={s['recall']} F1={s['f1']} "
                  f"(tp={s['tp']} fp={s['fp']} fn={s['fn']}, findings={s['n_findings']})")
    if verbose and out:
        macro_f1 = sum(s["f1"] for s in out.values()) / len(out)
        print(f"--- macro-F1 = {round(macro_f1, 3)} "
              f"(target: clean P=1.0, attack R=1.0) ---")
    return out


if __name__ == "__main__":
    import sys
    if "/app" not in sys.path:
        sys.path.insert(0, "/app")
    evaluate()
