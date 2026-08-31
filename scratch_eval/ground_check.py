"""Deterministic grounding guard: flag any timestamp / sha256 in a report narrative
that does NOT appear in the payload the model was given. The recurring judge ding
across every strategy is fabricated timestamps; this catches them without an LLM.
"""
import json, re, sys
from services.fusion import store, render

TS = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")   # to-second precision
SHA = re.compile(r"\b[a-f0-9]{64}\b")


def build_macro_payload(cid):
    g = store.load_graph(cid); d = store.get_case(cid) or {}
    ent, chars = store._llm_payload_budget(d)
    p = render.distilled(g, window=d.get("time_window") or None,
                         min_severity=d.get("min_severity", "informational"),
                         max_entities=ent, budget_chars=chars, detail="summary")
    return json.dumps(p, default=str)


def check(narrative, payload_str):
    pay = payload_str
    ts_all = set(TS.findall(narrative))
    ts_bad = sorted(t for t in ts_all if t not in pay)      # 19-char prefix not present
    sha_all = set(SHA.findall(narrative))
    sha_bad = sorted(h for h in sha_all if h not in pay)
    return {"timestamps_total": len(ts_all), "timestamps_ungrounded": ts_bad,
            "hashes_total": len(sha_all), "hashes_ungrounded": sha_bad}


if __name__ == "__main__":
    cid = sys.argv[1]
    pay = build_macro_payload(cid)
    import glob, os
    for fp in sorted(glob.glob(f"/tmp/eval_out/{cid}__*.md")):
        strat = os.path.basename(fp)[len(cid) + 2:-3]
        r = check(open(fp).read(), pay)
        print("  %-14s ts:%d ungrounded:%d %s | sha:%d ungrounded:%d %s" % (
            strat, r["timestamps_total"], len(r["timestamps_ungrounded"]),
            r["timestamps_ungrounded"][:3],
            r["hashes_total"], len(r["hashes_ungrounded"]), r["hashes_ungrounded"][:1]))
