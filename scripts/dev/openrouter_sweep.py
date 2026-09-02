#!/usr/bin/env python3
"""Probe EVERY model in the OpenRouter catalog and report which ones work.

The catalog is hundreds of routed models and "some of them don't work" is not
something you can answer by reading it -- routability depends on the account's
data policy, on credit, on whether a model is a batch-only or free-tier variant,
and on whether it accepts the parameters we send. So ask each one.

RUN IT IN THE BACKEND CONTAINER (that is where the catalog, the transport and
the saved API key live):

    docker cp scripts/dev/openrouter_sweep.py intact_backend:/tmp/sweep.py
    docker exec intact_backend sh -lc \
      'PYTHONPATH=/app python3 /tmp/sweep.py --out /data/openrouter_sweep'

The key is read from the saved Settings config -- never passed on the command
line, where it would land in shell history and the process table.

COST. One probe is a ~15-token prompt and at most --max-tokens output tokens
(default 8) per model. Across the whole catalog that is cents, and the 8 is
deliberate: at 1 token a reasoning model spends its entire budget on hidden
reasoning and returns an EMPTY string, which reads as a failure when the model
is perfectly fine. An HTTP 200 is the pass condition here, not the reply text.

It stops immediately on an account-level failure (no credit, bad key) rather
than attributing it to 388 models one at a time.
"""
import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.insert(0, "/app")

PROMPT = "Reply with exactly: OK"
SYSTEM = "You are a connectivity probe."

# Account-level, not model-level: the next 387 probes would report the same
# thing and bill for the privilege.
FATAL_CODES = {"no_credit", "invalid_key"}


def load_key():
    """The saved OpenRouter key, from Settings. Never from argv."""
    from services.storage import base
    row = base.get_connection().execute(
        "SELECT * FROM frontend_config").fetchone()
    if not row:
        return ""
    cfg = json.loads(row[1]) if isinstance(row[1], str) else (row[1] or {})
    return ((cfg.get("online_llm") or {}).get("api_key") or "").strip()


def catalog_models():
    """Every SELECTABLE model -- what the operator can actually pick in the UI.

    Deliberately search() and not load_catalog(): the raw catalog carries a
    handful of entries the picker filters out (meta-routers, and music models
    with no chat endpoint at all), and probing those would manufacture failures
    for models nobody can choose.
    """
    from services.llm_catalogs import openrouter
    return [m["id"] for m in openrouter.search(q="", limit=10000)["models"]]


def expected_bucket(model_id):
    """Failures that are a property of the VARIANT, not a broken model.

    Reported separately so a real regression is not buried under 40 entries
    that were never going to answer a synchronous request in the first place.
    """
    if model_id.endswith(":batch"):
        return "batch-only variant (asynchronous endpoint; cannot answer a live request)"
    return None


def probe(model_id, key, max_tokens, timeout):
    from services.agentic.analyzers._llm import call_llm
    cfg = {"agentic": {
        "llm_mode": "online",
        "online_llm": {"provider": "openrouter", "api_key": key, "model": model_id},
        "max_response_tokens": max_tokens,
    }}
    t0 = time.time()
    try:
        reply = call_llm(PROMPT, SYSTEM, cfg)
        # An empty 200 is a PASS. Small-budget reasoning models spend the whole
        # allowance on hidden reasoning and return "" -- the request worked.
        return {"model": model_id, "ok": True, "code": "ok",
                "reply": (reply or "")[:60], "empty_reply": not (reply or "").strip(),
                "ms": int((time.time() - t0) * 1000)}
    except Exception as e:                              # noqa: BLE001
        from services.fusion import llm_sim
        cls = llm_sim.classify_llm_failure(e)
        return {"model": model_id, "ok": False, "code": cls["code"],
                "reason": cls["reason"], "detail": f"{type(e).__name__}: {e}"[:300],
                "ms": int((time.time() - t0) * 1000)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/data/openrouter_sweep")
    ap.add_argument("--max-tokens", type=int, default=8)
    ap.add_argument("--workers", type=int, default=6)
    ap.add_argument("--timeout", type=int, default=90)
    ap.add_argument("--limit", type=int, default=0, help="probe only the first N (smoke test)")
    ap.add_argument("--only", default="", help="substring filter on the model id")
    args = ap.parse_args()

    key = load_key()
    if not key:
        print("No OpenRouter API key saved. Set it in Settings -> LLM "
              "(provider: openrouter) and re-run.", file=sys.stderr)
        return 2

    models = catalog_models()
    if args.only:
        models = [m for m in models if args.only in m]
    if args.limit:
        models = models[:args.limit]
    print(f"Probing {len(models)} model(s), {args.max_tokens} output tokens each, "
          f"{args.workers} at a time.", flush=True)

    results, fatal = [], None
    done = 0
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(probe, m, key, args.max_tokens, args.timeout): m
                   for m in models}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            done += 1
            if not r["ok"] and r["code"] in FATAL_CODES and fatal is None:
                fatal = r
                for f in futures:
                    f.cancel()
            if done % 25 == 0 or done == len(models):
                ok = sum(1 for x in results if x["ok"])
                print(f"  {done}/{len(models)} — {ok} passing", flush=True)
            if fatal:
                break

    if fatal:
        print(f"\nSTOPPED: {fatal['code']} on {fatal['model']} — {fatal.get('reason')}\n"
              f"That is an ACCOUNT-level failure, not a model one; every remaining "
              f"probe would report the same thing and bill for it.", file=sys.stderr)

    # Rate limiting is a moment in time, not a verdict on the model -- retry
    # those once, serially, before condemning them.
    retry = [r["model"] for r in results if not r["ok"] and r["code"] == "rate_limited"]
    if retry and not fatal:
        print(f"\nRetrying {len(retry)} rate-limited model(s) serially…", flush=True)
        for m in retry:
            time.sleep(2)
            fresh = probe(m, key, args.max_tokens, args.timeout)
            fresh["retried"] = True
            results = [x for x in results if x["model"] != m] + [fresh]

    os.makedirs(args.out, exist_ok=True)
    results.sort(key=lambda r: r["model"])

    passing = [r for r in results if r["ok"]]
    failing = [r for r in results if not r["ok"]]
    expected = [r for r in failing if expected_bucket(r["model"])]
    broken = [r for r in failing if not expected_bucket(r["model"])]

    with open(os.path.join(args.out, "results.json"), "w") as fh:
        json.dump({"probed": len(results), "passing": len(passing),
                   "expected_failures": len(expected), "broken": len(broken),
                   "fatal": fatal, "results": results}, fh, indent=2)

    by_code = {}
    for r in broken:
        by_code.setdefault(r["code"], []).append(r)

    lines = [f"# OpenRouter catalog sweep",
             "",
             f"- probed: **{len(results)}**",
             f"- working: **{len(passing)}**",
             f"- failing for a reason that is a property of the variant: **{len(expected)}**",
             f"- genuinely not working: **{len(broken)}**", ""]
    if fatal:
        lines += [f"> **Stopped early**: `{fatal['code']}` on `{fatal['model']}`. "
                  f"That is account-level, so the counts above are partial.", ""]
    if broken:
        lines += ["## Not working", ""]
        for code, rows in sorted(by_code.items(), key=lambda kv: -len(kv[1])):
            lines += [f"### `{code}` — {len(rows)} model(s)", "",
                      f"{rows[0].get('reason', '')}", "",
                      "| model | detail |", "|---|---|"]
            for r in sorted(rows, key=lambda x: x["model"]):
                lines.append(f"| `{r['model']}` | {r.get('detail','').replace('|','/')[:160]} |")
            lines.append("")
    if expected:
        lines += ["## Expected failures (not a defect)", "",
                  "| model | why |", "|---|---|"]
        for r in expected:
            lines.append(f"| `{r['model']}` | {expected_bucket(r['model'])} |")
        lines.append("")
    quiet = [r for r in passing if r.get("empty_reply")]
    if quiet:
        lines += [f"## Working, but answered with an empty string ({len(quiet)})", "",
                  "These returned HTTP 200 with no text: the whole token budget went to "
                  "hidden reasoning. They are working — a 1-token probe would have "
                  "misreported every one of them as broken.", ""]
        lines += ["| model |", "|---|"] + [f"| `{r['model']}` |" for r in quiet] + [""]
    lines += ["## Working", "", "| model | ms |", "|---|---|"]
    for r in sorted(passing, key=lambda x: x["model"]):
        lines.append(f"| `{r['model']}` | {r['ms']} |")

    md = os.path.join(args.out, "REPORT.md")
    with open(md, "w") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"\n{len(passing)} working / {len(broken)} broken / {len(expected)} expected-fail")
    print(f"Wrote {md}")
    return 1 if fatal else 0


if __name__ == "__main__":
    sys.exit(main())
