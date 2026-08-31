"""Edge cases the corpus does not cover (deterministic).

  M1 masking at corpus scale — with masking ON across all 41 scenarios, does any real
     hostname/account leak into the text the model would receive?
  X1 clock skew — hosts whose clocks disagree by hours. Does the timeline mis-order,
     and is a skewed host still attributed correctly?
  X2 contradictory evidence — the same entity reported with conflicting attributes by
     two artifacts. Forensic integrity says KEEP both with provenance, never silently
     overwrite.
  X3 oversized / Unicode / control characters — a 200 KB command line, RTL overrides,
     null bytes, emoji. Must not crash, must not blow the payload.
  X4 single-event case — one finding, one host. The smallest possible case must still
     render a coherent report.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_edge_cases.py
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, render, llm_sim  # noqa: E402
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
_T = "Windows.Hayabusa.Rules"
_PS = "Generic.System.Pstree"
_ACC = "Windows.EventLogs.CondensedAccountUsage"


def fuse(tele, cid, **kw):
    e, r = map_agentic(tele, run_id="edge", hostnames={})
    return correlate.assemble(cid, [(e, r)], ["edge"], **kw)


def m1_masking_scale():
    """Every real host/account must be pseudonymised in the payload the model sees."""
    tele = corpus.build_all_telemetry()
    g = fuse(tele, "m1")
    try:
        from services.data_anonymizer import DataAnonymizer
        mask = DataAnonymizer(custom_patterns=[])
        llm_sim._build_mask_mapping(g, mask)
    except Exception as e:  # noqa: BLE001
        return {"error": str(e)[:120], "pass": False}
    payload = json.dumps(render.distilled(g, max_entities=400, budget_chars=708000,
                                          detail="summary"), default=str)
    masked = llm_sim._apply_mask(payload, mask)
    hosts = [a.label for a in g.by_type("asset") if a.label]
    accts = [e.label for e in g.by_type("account") if e.label]
    leaked_h = sorted({h for h in hosts if h and h in masked})
    leaked_a = sorted({a for a in accts if a and a in masked})
    reverted = llm_sim._revert_mask(masked, mask)
    return {"hosts": len(hosts), "accounts": len(accts),
            "leaked_hosts": leaked_h[:5], "leaked_accounts": leaked_a[:5],
            "round_trip_ok": reverted == payload,
            "pass": not leaked_h and not leaked_a}


def x1_clock_skew():
    """Two hosts, clocks 6h apart, same real-world attack sequence."""
    tele = {_T: [
        {"Computer": "SKEW-A", "Title": "Mimikatz LSASS Credential Dumping",
         "Level": "crit", "EventTime": "2026-12-01T09:00:00Z"},
        # SKEW-B's clock is 6h BEHIND: its later real event carries an earlier stamp
        {"Computer": "SKEW-B", "Title": "Rclone Cloud Exfiltration", "Level": "high",
         "EventTime": "2026-12-01T03:30:00Z"},
    ]}
    g = fuse(tele, "x1")
    tl = render.timeline(g)
    order = [r["host"] for r in tl]
    tss = [r["ts"] for r in tl if r.get("ts")]
    return {"rows": len(tl), "order": order, "chronological_by_stamp": tss == sorted(tss),
            "both_hosts_present": len({h for h in order if h}) == 2,
            "pass": len(tl) == 2 and len({h for h in order if h}) == 2}


def x2_contradictory():
    """Same process reported with conflicting attributes by two artifacts."""
    tele = {_PS: [
        {"Computer": "CONF-A", "Pid": 4242, "Name": "svchost.exe",
         "CommandLine": "svchost.exe -k netsvcs", "CreateTime": "2026-12-01T08:00:00Z"},
        {"Computer": "CONF-A", "Pid": 4242, "Name": "svchost.exe",
         "CommandLine": "TOTALLY DIFFERENT COMMANDLINE", "CreateTime": "2026-12-01T08:00:00Z"},
    ]}
    g = fuse(tele, "x2")
    procs = [e for e in g.entities.values() if e.type == "process"]
    kept_both = False
    conflict_flagged = False
    for p in procs:
        obs = p.attrs.get("cmdline_observations") or p.attrs.get("ev_cmdline_observations")
        if obs:
            kept_both = True
        if "conflict" in (p.flags or []):
            conflict_flagged = True
    return {"process_entities": len(procs), "kept_both_values": kept_both,
            "conflict_flagged": conflict_flagged,
            "pass": kept_both or conflict_flagged}


def x3_hostile_strings():
    """Oversized, Unicode, RTL-override and control characters must not crash."""
    huge = "A" * 200_000
    tele = {_PS: [
        {"Computer": "EDGE-A", "Pid": 1, "Name": "big.exe", "CommandLine": huge,
         "CreateTime": "2026-12-01T08:00:00Z"},
        {"Computer": "EDGE-A", "Pid": 2, "Name": "uni.exe",
         "CommandLine": "cmd \u202egnp.exe \x00 \U0001f600 \u200b unicode",
         "CreateTime": "2026-12-01T08:01:00Z"},
    ]}
    try:
        g = fuse(tele, "x3")
        p = json.dumps(render.distilled(g, max_entities=100, budget_chars=708000,
                                        detail="explicit"), default=str)
        md = render.facts_md(g, detail="summary", narrated=True)
        return {"entities": len(g.entities), "payload_chars": len(p),
                "report_chars": len(md),
                "payload_bounded": len(p) < 708000, "pass": True}
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {e}"[:160], "pass": False}


def x4_single_event():
    """The smallest possible case must still produce a coherent report."""
    tele = {_T: [{"Computer": "SOLO-A", "Title": "Mimikatz LSASS Credential Dumping",
                  "Level": "crit", "EventTime": "2026-12-01T08:00:00Z"}]}
    g = fuse(tele, "x4")
    md = render.facts_md(g, detail="summary", narrated=True)
    alt, _ = render._resolve_altitude(g)
    return {"findings": len(g.findings), "altitude": alt, "report_chars": len(md),
            "has_timeline": "## Timeline of Events" in md,
            "has_limitations": "## Limitations & Assumptions" in md,
            "pass": len(g.findings) == 1 and alt == "focused" and
                    "## Limitations & Assumptions" in md}


def main():
    res = {"M1": m1_masking_scale(), "X1": x1_clock_skew(), "X2": x2_contradictory(),
           "X3": x3_hostile_strings(), "X4": x4_single_event()}
    lines = ["# Edge cases (deterministic)", "", "| Test | What | Result | |",
             "|---|---|---|:--:|"]
    labels = {
        "M1": "masking at corpus scale — any real host/account leaking?",
        "X1": "clock skew — hosts 6h apart",
        "X2": "contradictory evidence — conflicting attrs kept?",
        "X3": "hostile strings — 200 KB cmdline, RTL, NUL, emoji",
        "X4": "single-event case — smallest possible report",
    }
    for k, v in res.items():
        detail = ", ".join(f"{a}={b}" for a, b in v.items()
                           if a != "pass" and not isinstance(b, list) or (isinstance(b, list) and b))
        lines.append(f"| **{k}** | {labels[k]} | {detail[:150]} | "
                     f"{'✅' if v.get('pass') else '❌'} |")
    md = "\n".join(lines) + "\n"
    open(f"{OUT}/edge_cases.md", "w").write(md)
    json.dump(res, open(f"{OUT}/edge_cases.json", "w"), indent=2, default=str)
    print(md)


if __name__ == "__main__":
    main()
