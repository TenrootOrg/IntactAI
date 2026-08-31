"""Track E — synthetic agentic-scale enablement (deterministic smoke).

Proves a SYNTHETIC case can drive the agentic evidence()/pivot() tools — which
synth graphs otherwise can't (no event entities / EvidenceRefs). This unblocks
running the Track-B variance matrix at 100-host scale instead of only the ~8 real
cases. No model call: we exercise the tool dispatch directly.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/agentic_synthscale.py
"""
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # scratch_eval
from services.fusion import store, investigate  # noqa: E402
import synth_graph  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
RESULTS = []


def rec(name, ok, detail):
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} — {detail}")


class _Patch:
    def __init__(self, obj, **a):
        self.obj, self.a, self.s = obj, a, {}

    def __enter__(self):
        for k, v in self.a.items():
            self.s[k] = getattr(self.obj, k, None); setattr(self.obj, k, v)
        return self

    def __exit__(self, *_):
        for k, v in self.s.items():
            setattr(self.obj, k, v)


def run_shape(shape, hosts, span, findings):
    g, d = synth_graph.synth(hosts, span, findings)
    raw, rid = synth_graph.add_events(g, d, per_finding=3)
    cid = g.case_id
    n_events = sum(1 for e in g.entities.values() if e.type == "event")

    # Stub the store so the tools resolve against this in-memory synth case + its
    # raw source (exactly how a synth-mode Track-B run would wire it).
    def fake_run(_rid):
        return {"details": {}} if _rid == rid else {}
    with _Patch(store, load_graph=lambda c: g, get_case=lambda c: d,
                _agentic_collected_data=lambda r, det: (raw if r == rid else {})):
        # pivot on a known account substring
        pv = investigate._tool(cid, "pivot", {"value": "svc"})
        rec(f"{shape}: pivot resolves events", pv.get("total_matches", 0) > 0,
            f"{hosts}h/{findings}f -> {n_events} event entities, "
            f"pivot total_matches={pv.get('total_matches')}")
        # evidence on the first finding that has refs
        fid = next((f.id for f in g.findings if f.evidence), None)
        ev = store.get_evidence_rows(cid, fid, max_rows=6) if fid else []
        rec(f"{shape}: evidence resolves raw rows", len(ev) > 0,
            f"finding {fid} -> {len(ev)} raw rows"
            + (f" (e.g. {list(ev[0]['row'].keys())})" if ev else ""))
        # list_findings + search still work (graph-only tools)
        lf = investigate._tool(cid, "list_findings", {"limit": 5})
        rec(f"{shape}: list_findings", len(lf) > 0, f"{len(lf)} findings")


def main():
    print("=== Track E — synthetic agentic-scale enablement (smoke) ===")
    # one small + one large shape to prove it holds at scale
    for shape, (h, s, f) in [("few_short", (3, 7, 14)), ("many_long", (100, 365, 220))]:
        run_shape(shape, h, s, f)
    ok = sum(1 for r in RESULTS if r["ok"])
    json.dump({"track": "E", "checks": RESULTS,
               "findings": [] if ok == len(RESULTS) else
               [{"id": "E-gap", "title": "synth agentic tool did not resolve",
                 "severity": "medium", "status": "FINDING",
                 "detail": json.dumps([r for r in RESULTS if not r["ok"]]),
                 "repro": "campaign/agentic_synthscale.py"}]},
              open(f"{OUT}/agentic_synthscale.json", "w"), indent=2)
    md = ["# Track E — synthetic agentic-scale enablement", "",
          f"{ok}/{len(RESULTS)} checks passed. Proves synth cases can drive "
          "evidence()/pivot() (previously report-path only), unblocking Track-B "
          "variance testing at 100-host scale.", "",
          "| Check | Result |", "|---|---|"]
    md += [f"| {r['check']} | {'PASS' if r['ok'] else 'FAIL'} — {r['detail']} |" for r in RESULTS]
    open(f"{OUT}/agentic_synthscale.md", "w").write("\n".join(md) + "\n")
    print(f"\n{ok}/{len(RESULTS)} passed -> {OUT}/agentic_synthscale.md")


if __name__ == "__main__":
    main()
