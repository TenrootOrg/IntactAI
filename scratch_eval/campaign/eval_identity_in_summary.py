"""C12 — does the SUMMARY say "one actor on N machines", or N unrelated users?

Tonight's fix makes a cross-host finding appear when one actor's account is written
differently per host. This checks whether that actually changes what the ANALYST READS:
the same case, summarised, scored for whether it attributes the activity to ONE identity.

Case: one actor, three account FORMS across three hosts + a real attack chain.
  corp\\intruder (WKS-CHAIN01) | intruder@corp.local (WKS-CHAIN02) | intruder (DC-CHAIN01)

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_identity_in_summary.py [N]
"""
import json, os, re, sys
sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion import render, store, llm_sim  # noqa: E402
import eval_campaign_chain as cc  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()
N = int(sys.argv[1]) if sys.argv[1:] else 6

# says ONE actor spanning hosts
ONE_ACTOR = re.compile(r"\b(same (actor|identity|user|account|person)|one (actor|identity|person)"
                       r"|single (actor|identity|user|account|person)|the actor"
                       r"|across (all )?(three|3|multiple) hosts|same principal)\b", re.I)
# names the identity
NAMES_ID = re.compile(r"intruder", re.I)
# treats them as separate people
SEPARATE = re.compile(r"\b(three (different|separate|distinct) (users|accounts|identities)"
                      r"|unrelated (users|accounts))\b", re.I)


def main():
    g = cc.fuse(cc.telemetry([(cc.H1, "corp\\intruder"), (cc.H2, "intruder@corp.local"),
                              (cc.DC, "intruder")]), "c12")
    xh = [f for f in g.findings if f.kind == "cross_host"]
    print(f"case: {len(g.by_type('asset'))} hosts, {len(g.findings)} findings, "
          f"{len(xh)} cross-host", flush=True)
    payload = json.dumps(render.distilled(g, max_entities=200, budget_chars=300000,
                                          detail="summary"), default=str)
    rows = []
    for i in range(1, N + 1):
        rid = ws.create_automation_run("c12", f"r{i}")
        try:
            rep = llm_sim._real_llm(llm_sim.REPORT_SYSTEM_PROMPT_MACRO, payload, run_id=rid)
        except Exception as e:
            rep = f"(ERROR {e})"
        one = bool(ONE_ACTOR.search(rep)); named = bool(NAMES_ID.search(rep))
        sep = bool(SEPARATE.search(rep))
        rows.append({"run": i, "one_actor": one, "names_identity": named,
                     "treats_separate": sep, "text": rep[:400]})
        print(f"[{i}/{N}] one_actor={one} names_identity={named} separate={sep} :: "
              f"{rep[:70].strip()}", flush=True)
    oa = sum(r["one_actor"] for r in rows); nm = sum(r["names_identity"] for r in rows)
    sp = sum(r["treats_separate"] for r in rows)
    md = ["# C12 — identity attribution in the summary", "",
          "One actor, three account FORMS, three hosts. Does the summary say one actor, "
          "or read as unrelated users?", "",
          f"- cross-host findings in the case: **{len(xh)}** (0 before tonight's fix)",
          f"- **attributes to ONE actor: {oa}/{N}**",
          f"- names the identity: {nm}/{N}",
          f"- treats them as separate people: {sp}/{N} (lower is better)", "",
          "| Run | One actor | Names identity | Separate |", "|---|:--:|:--:|:--:|"]
    for r in rows:
        md.append(f"| {r['run']} | {'✅' if r['one_actor'] else '—'} | "
                  f"{'✓' if r['names_identity'] else '—'} | "
                  f"{'❌' if r['treats_separate'] else 'no'} |")
    open(f"{OUT}/identity_in_summary.md", "w").write("\n".join(md) + "\n")
    json.dump({"n": N, "one_actor": oa, "rows": rows},
              open(f"{OUT}/identity_in_summary.json", "w"), indent=2, default=str)
    print("\n".join(md[:8]))


if __name__ == "__main__":
    main()
