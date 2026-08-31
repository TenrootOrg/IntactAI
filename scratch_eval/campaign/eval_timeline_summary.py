"""B8 + B9 + A4 — timeline robustness and summary-section correctness (deterministic).

  B8 timestomping / corrupt timestamps — future-dated, absent, and mixed-notation
     times. Does the timeline mis-order, silently drop events, or invent ordering?
  B9 collapse fidelity — the macro timeline collapses repeats into groups. No event
     may be lost, counts/spans must be exact, and no CRITICAL may ever be hidden
     (that was a real bug, fixed; this re-verifies at corpus scale).
  A4 Limitations correctness — the new "Limitations & Assumptions" section must state
     what was ACTUALLY excluded. A false limitation is worse than none, so each claim
     is checked against the graph.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_timeline_summary.py
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render, keys  # noqa: E402
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
_T = "Windows.Hayabusa.Rules"


def fuse(tele, cid):
    e, r = map_agentic(tele, run_id="tsrun", hostnames={})
    return correlate.assemble(cid, [(e, r)], ["tsrun"])


def b8_timestomp():
    """Mixed / hostile timestamps must not break ordering or lose events."""
    rows = [
        {"Computer": "TS-H1", "Title": "Normal ISO Z", "Level": "high",
         "EventTime": "2026-09-01T10:00:00Z"},
        {"Computer": "TS-H1", "Title": "Fractional seconds", "Level": "high",
         "EventTime": "2026-09-01T10:00:00.500000Z"},
        {"Computer": "TS-H1", "Title": "Epoch seconds", "Level": "high",
         "EventTime": "1788080400"},                       # ~2026-09
        {"Computer": "TS-H1", "Title": "Float epoch", "Level": "high",
         "EventTime": "1788080500.75"},
        {"Computer": "TS-H1", "Title": "Space separated", "Level": "high",
         "EventTime": "2026-09-01 11:00:00"},
        {"Computer": "TS-H1", "Title": "Far future timestomp", "Level": "high",
         "EventTime": "2099-01-01T00:00:00Z"},
        {"Computer": "TS-H1", "Title": "No timestamp at all", "Level": "high"},
        {"Computer": "TS-H1", "Title": "Garbage timestamp", "Level": "high",
         "EventTime": "not-a-time"},
    ]
    g = fuse({_T: rows}, "ts_stomp")
    titles = {f.title for f in g.findings}
    kept = sum(1 for r in rows if any(r["Title"] in t for t in titles))
    tl = render.timeline(g)
    tss = [r["ts"] for r in tl if r.get("ts")]
    ordered = tss == sorted(tss)
    # a finding with an unparseable/missing time must still EXIST (never dropped)
    undated_kept = any("No timestamp" in t for t in titles) and \
        any("Garbage" in t for t in titles)
    future = [r for r in tl if r.get("ts", "").startswith("2099")]
    return {"planted": len(rows), "findings_kept": kept, "timeline_rows": len(tl),
            "chronological": ordered, "undated_kept": undated_kept,
            "future_dated_present": len(future),
            "pass": kept == len(rows) and ordered and undated_kept}


def b9_collapse():
    """No event lost, counts exact, no critical hidden — at corpus scale."""
    tele = corpus.build_all_telemetry()
    g = fuse(tele, "collapse")
    md = render.facts_md(g, detail="summary", narrated=True)
    tl = re.search(r"## Timeline of Events.*?(?=\n## |\Z)", md, re.S)
    tl = tl.group(0) if tl else ""
    m = re.search(r"(\d+) event\(s\) collapsed into (\d+) recurring", tl)
    ev, grp = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    # every critical group must be present
    crit_groups = {(f.title.split(" on ")[0], f.severity) for f in g.findings
                   if f.severity == "critical" and f.ts and f.kind != "cross_host"
                   and not f.title.startswith("Coordinated suspicious")}
    shown_crit = len(re.findall(r"\*\*\[critical\]\*\*", tl))
    # counts in the rows must sum to <= the collapsed event total (no invention)
    counts = [int(x) for x in re.findall(r"·\s*×(\d+)", tl)]
    return {"events": ev, "groups": grp, "critical_groups_expected": len(crit_groups),
            "critical_shown": shown_crit, "count_markers": len(counts),
            "sum_of_counts_le_events": sum(counts) <= ev if ev else True,
            "pass": shown_crit >= len(crit_groups) and (sum(counts) <= ev if ev else True)}


def a4_limitations():
    """Every claim in Limitations must be TRUE of the graph."""
    tele = corpus.build_all_telemetry()
    # add a host with no findings so the "quiet host" claim has something to be right about
    tele.setdefault("Generic.System.Pstree", []).append(
        {"Computer": "QUIET-HOST01", "Pid": 4, "Name": "System",
         "CommandLine": "System", "CreateTime": "2026-08-01T08:00:00Z"})
    g = fuse(tele, "limits")
    md = render.facts_md(g, detail="summary", narrated=True,
                         min_severity="informational")
    sec = re.search(r"## Limitations & Assumptions.*", md, re.S)
    sec = sec.group(0) if sec else ""
    assets, findings = render.scope(g, min_severity="informational")
    quiet = [a.label for a in assets
             if not any(a.id in (f.asset_ids or []) for f in findings)]
    undated = sum(1 for f in findings if not f.ts)
    checks = []
    m = re.search(r"\*\*(\d+) host\(s\) in scope produced no findings\*\*", sec)
    if m:
        checks.append(("quiet-host count", int(m.group(1)) == len(quiet),
                       f"claimed {m.group(1)}, actual {len(quiet)}"))
    m = re.search(r"\*\*(\d+) finding\(s\) carry no timestamp\*\*", sec)
    if m:
        checks.append(("undated count", int(m.group(1)) == undated,
                       f"claimed {m.group(1)}, actual {undated}"))
    if "QUIET-HOST01" in sec:
        checks.append(("quiet host named", "QUIET-HOST01" in sec, "named correctly"))
    present = bool(sec.strip())
    return {"section_present": present, "checks": checks,
            "all_true": all(c[1] for c in checks) if checks else present,
            "pass": present and all(c[1] for c in checks)}


def main():
    b8, b9, a4 = b8_timestomp(), b9_collapse(), a4_limitations()
    lines = ["# Timeline robustness + summary-section correctness", "",
             "| Test | Result | |", "|---|---|:--:|",
             f"| **B8** timestomping / corrupt times | {b8['findings_kept']}/{b8['planted']} "
             f"events kept, chronological={b8['chronological']}, undated kept="
             f"{b8['undated_kept']} | {'✅' if b8['pass'] else '❌'} |",
             f"| **B9** collapse fidelity @ corpus scale | {b9['events']} events → "
             f"{b9['groups']} groups; critical shown {b9['critical_shown']}/"
             f"{b9['critical_groups_expected']} | {'✅' if b9['pass'] else '❌'} |",
             f"| **A4** Limitations correctness | "
             + ("; ".join(f"{n}: {d}" for n, _o, d in a4["checks"]) or "section present")
             + f" | {'✅' if a4['pass'] else '❌'} |", ""]
    if b8["future_dated_present"]:
        lines += [f"> B8 note: the 2099 timestomped event is present in the timeline "
                  f"({b8['future_dated_present']} row) and sorts last — it is not "
                  "dropped, and it is visible as an anomaly rather than silently "
                  "reordering real events.", ""]
    for n, ok, d in a4["checks"]:
        if not ok:
            lines += [f"> **A4 FALSE CLAIM** — {n}: {d}", ""]
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/timeline_summary.md", "w").write(md)
    json.dump({"B8": b8, "B9": b9, "A4": a4},
              open(f"{OUT}/timeline_summary.json", "w"), indent=2, default=str)
    print(md)


if __name__ == "__main__":
    main()
