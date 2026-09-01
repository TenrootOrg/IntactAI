"""D14 + D16 — CHAT accuracy vs simulation ground truth.

Chat (the "Ask" path) has only ever been used as a baseline arm; it has never been
scored on its own against an answer key. It differs from Investigate in one critical
way: chat gets ONE distilled payload and answers from it — there is no fetch-to-cite
tool loop — so it is where fabrication is most likely.

Same ground-truth questions as the investigation harness, so the two are directly
comparable (D15). Negative controls included: chat has no grounding guarantee, so a
clean negative-control record here is worth more than anywhere else.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/eval_chat_accuracy.py [N]
"""
import json
import os
import re
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from services.fusion.mappers.agentic import map_agentic  # noqa: E402
from services.fusion import correlate, store, llm_sim  # noqa: E402
import attack_corpus as corpus  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()

# Denial detector for negative controls — shape, not literal phrases.
_NEG = re.compile(r"\bno\b[^.]{0,30}\b(evidence|indication|sign|mention|trace|activity|match|"
                  r"finding|findings|result|results|record|records)\b"
                  r"|\bnot\b[^.]{0,25}\b(observed|present|detected|found|establish|established|"
                  r"show|shown|prove|proven|confirm|confirmed|indicate|reveal)\b"
                  r"|\bdid not\b|\bnone\b|\bno such\b", re.I)

# Neutral phrasing throughout (the anchoring A/B proved loaded premises measure the
# wrong thing). Mirrors the investigation set so chat vs investigate is comparable.
QUESTIONS = [
    {"q": "Which host shows LSASS credential dumping, and what tool was used?",
     "kw": ["mimikatz"], "host": "wks-eval01", "present": True},
    {"q": "Was a Kerberos ticket attack (Rubeus / Kerberoasting) seen? On which host?",
     "kw": ["rubeus", "kerber"], "host": "wks-eval02", "present": True},
    {"q": "Which single account appears on more than one host?",
     "kw": ["svc_backup"], "host": "wks-eval04", "present": True},
    {"q": "Was Windows Defender disabled or tampered with, and where?",
     "kw": ["defender"], "host": "wks-eval02", "present": True},
    {"q": "Is there ransomware or shadow-copy deletion activity? On which host?",
     "kw": ["ransomware", "shadow"], "host": "wks-eval07", "present": True},
    {"q": "Was data exfiltrated to cloud storage, and from which host?",
     "kw": ["rclone", "exfil"], "host": "wks-eval04", "present": True},
    {"q": "What process injection was observed and on which host?",
     "kw": ["inject", "explorer", "svchost"], "host": "wks-eval01", "present": True},
    {"q": "Was NTDS.dit extracted from a domain controller? Which host?",
     "kw": ["ntds"], "host": "wks-eval02", "present": True},
    # NEGATIVE CONTROLS — never simulated; chat has no tool grounding, so this is the
    # sharpest fabrication test in the whole campaign.
    {"q": "Is there evidence of cryptocurrency mining (XMRig / Monero)?",
     "kw": ["no evidence", "not find", "none", "no indication", "did not", "not observed",
            "no mention", "not present"], "present": False},
    {"q": "Was there any macOS or Linux malware in this environment?",
     "kw": ["no evidence", "not find", "none", "no indication", "windows", "did not",
            "not observed", "no mention"], "present": False},
    {"q": "Did an attacker use a printer-spooler exploit (PrintNightmare) here?",
     "kw": ["no evidence", "not find", "none", "no indication", "did not", "not observed",
            "no mention", "not present"], "present": False},
]


def main():
    n_rep = int(sys.argv[1]) if sys.argv[1:] else 1
    tele = corpus.build_all_telemetry()
    ents, rels = map_agentic(tele, run_id="evalrun", hostnames={})
    g = correlate.assemble("gt_chat", [(ents, rels)], ["evalrun"])
    rows = []
    for rep in range(1, n_rep + 1):
        for i, qd in enumerate(QUESTIONS, 1):
            rid = ws.create_automation_run("chat_acc", f"r{rep}q{i}")
            try:
                ans = llm_sim.chat(g, qd["q"], history=[], window=None,
                                   min_severity="informational", run_id=rid,
                                   full_context=True, require_llm=True, mask=None)
            except Exception as e:  # noqa: BLE001
                ans = f"(ERROR {e})"
            a = (ans or "").lower()
            if qd["present"]:
                kw = any(k in a for k in qd["kw"])
            else:
                # A literal phrase list mis-scores real denials: "No DIRECT evidence of
                # cryptocurrency mining" does not contain "no evidence". Match the SHAPE
                # of a denial instead (measured: this recovered 1/3 -> 3/3).
                kw = bool(_NEG.search(ans or ""))
            host_ok = (qd["host"] in a) if qd["present"] else True
            ok = kw and host_ok
            rows.append({"rep": rep, "q": qd["q"], "present": qd["present"],
                         "kw": kw, "host": host_ok, "ok": ok, "answer": ans[:260]})
            print(f"[r{rep} {i}/{len(QUESTIONS)}] {'✅' if ok else '❌'} "
                  f"present={qd['present']} kw={kw} host={host_ok} :: "
                  f"{(ans or '')[:70].strip()}", flush=True)

    pres = [r for r in rows if r["present"]]
    neg = [r for r in rows if not r["present"]]
    pc, nc = sum(r["ok"] for r in pres), sum(r["ok"] for r in neg)
    tot = pc + nc
    md = ["# Chat (Ask path) accuracy vs simulation", "",
          "Chat answers from ONE distilled payload with no fetch-to-cite tool loop, so "
          "this is where fabrication is most likely. Neutral phrasing throughout.", "",
          f"**Chat accuracy: {tot}/{len(rows)} — plants {pc}/{len(pres)}, "
          f"negative controls {nc}/{len(neg)} clean.**", "",
          "| # | Question | Type | Correct | KW | Host | Answer (head) |",
          "|---|---|---|:--:|:--:|:--:|---|"]
    for i, r in enumerate(rows, 1):
        md.append(f"| {i} | {r['q'][:46]} | {'plant' if r['present'] else 'neg-ctrl'} | "
                  f"{'✅' if r['ok'] else '❌'} | {'✓' if r['kw'] else '—'} | "
                  f"{'✓' if r['host'] else '—'} | "
                  f"{(r['answer'] or '')[:56].strip().replace(chr(10),' ')} |")
    open(f"{OUT}/chat_accuracy.md", "w").write("\n".join(md) + "\n")
    json.dump({"rows": rows, "plants": [pc, len(pres)], "neg": [nc, len(neg)]},
              open(f"{OUT}/chat_accuracy.json", "w"), indent=2, default=str)
    print("\n".join(md[:8]))


if __name__ == "__main__":
    main()
