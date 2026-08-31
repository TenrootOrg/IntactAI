"""Empirically determine the REAL usable context of the configured model.

The codex catalog advertises context_length=272,000 for gpt-5.6-sol (enriched_from
'codex-cli'), and the payload budget is derived from it — giving 708,000 chars
(~177k tokens). The operator states the real model has 1,000,000. If true, the
product is using ~24% of the available window and sending far less evidence to the
model than it could; if false, raising the budget would break every report.

Guessing either way is unacceptable, so this MEASURES it: send prompts of increasing
size through the real transport and record which sizes succeed. The task is trivial
("reply with one word") so the output is tiny and only the INPUT size is under test.

  cd /app/scratch_eval && PYTHONPATH=/app python3 campaign/probe_context_limit.py
"""
import json
import os
import sys
import time

sys.path.insert(0, "/app")
from services.fusion import llm_sim, store  # noqa: E402

OUT = "/tmp/eval_out/campaign"
os.makedirs(OUT, exist_ok=True)
ws = store._ws()

SYSTEM = ("You are a size probe. Reply with exactly one word: OK. "
          "Ignore the filler content entirely.")
# token targets to probe (chars ~= tokens * 4)
TARGETS = [150_000, 250_000, 350_000, 500_000, 700_000, 900_000]


def _filler(tokens):
    """Realistic-ish filler so the provider can't trivially compress it."""
    unit = ('{"host":"WKS-%05d","detection":"SIGMA rule fired","severity":"high",'
            '"ts":"2026-08-01T10:00:00Z","cmd":"powershell -enc AAAA"} ')
    n = (tokens * 4) // len(unit % 0) + 1
    return "".join(unit % i for i in range(n))


def main():
    rows = []
    for tok in TARGETS:
        body = _filler(tok)
        chars = len(body)
        rid = ws.create_automation_run("ctx_probe", f"{tok}")
        t0 = time.time()
        ok, err, ans = False, "", ""
        try:
            ans = llm_sim._real_llm(SYSTEM, body, run_id=rid) or ""
            ok = True
        except Exception as e:  # noqa: BLE001
            err = f"{type(e).__name__}: {e}"[:200]
        dt = time.time() - t0
        m = (ws.get_automation_run(rid) or {}).get("llm_metrics") or {}
        rows.append({"target_tokens": tok, "chars": chars, "ok": ok,
                     "seconds": round(dt, 1), "reported_input_tokens": m.get("input_tokens"),
                     "error": err, "answer": (ans or "")[:60]})
        print(f"[{tok:>7,} tok / {chars:>10,} chars] "
              f"{'OK ' if ok else 'FAIL'} {dt:>6.1f}s "
              f"reported_in={m.get('input_tokens')} {err[:80]}", flush=True)
        if not ok:
            print("  -> stopping at first failure", flush=True)
            break

    largest_ok = max([r["target_tokens"] for r in rows if r["ok"]], default=0)
    md = ["# Real usable context — measured, not assumed", "",
          "The codex catalog advertises **272,000** tokens for `gpt-5.6-sol` "
          "(`enriched_from: codex-cli`), which sets the payload budget at 708,000 "
          "chars (~177k tokens). The operator states the model is **1,000,000**. "
          "This probes the transport directly.", "",
          f"**Largest input that succeeded: {largest_ok:,} tokens.**", "",
          "| Target tokens | Chars sent | Result | Seconds | Reported input tokens |",
          "|---|---|:--:|---|---|"]
    for r in rows:
        md.append(f"| {r['target_tokens']:,} | {r['chars']:,} | "
                  f"{'✅ OK' if r['ok'] else '❌ FAIL'} | {r['seconds']} | "
                  f"{r['reported_input_tokens']} |")
    if any(not r["ok"] for r in rows):
        bad = next(r for r in rows if not r["ok"])
        md += ["", f"> First failure at {bad['target_tokens']:,} tokens: "
               f"`{bad['error']}`"]
    md += ["", "## What this decides",
           "- If the largest success is well above 272k, the catalog under-reports the "
           "window and the budget can be raised — more evidence per report.",
           "- If it fails at/near 272k, the catalog is right and the current budget is "
           "correctly calibrated; the operator's 1M figure would be the model's raw "
           "spec rather than what this CLI transport actually accepts."]
    open(f"{OUT}/context_probe.md", "w").write("\n".join(md) + "\n")
    json.dump(rows, open(f"{OUT}/context_probe.json", "w"), indent=2, default=str)
    print("\n".join(md[:8]))


if __name__ == "__main__":
    main()
