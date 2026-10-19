"""Test the AI models of the big vendors on OpenRouter: one 1-token chat call each.

OpenRouter lists ~470 models; an account with a zero-data-retention policy cannot
use many of them, and some list with no endpoint. The picker offered all of them
alike. Update catalog starts this as a Settings -> Actions job; the picker then
marks and orders the models it tested.

NOTHING HERE MAY RAISE OUT: one model's failure is that model's result, a job that
dies ends as a failed run with its reason, a bad results file reads as "never
tested". The case engine never sees any of it.
"""
import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import requests

PROBES_PATH = "/app/data/llm_model_probes.json"
CHAT_URL = "https://openrouter.ai/api/v1/chat/completions"
# Vendors tested, by popularity and staying power (2026-10-19, the operator's choice).
# Models of any other vendor stay in the picker, untested.
VENDORS = ("openai", "anthropic", "google", "meta-llama", "meta", "mistralai",
           "deepseek", "qwen", "x-ai", "amazon", "microsoft")
WORKERS = 6
TIMEOUT_SEC = 45
# These many first results all outages (no network, key refused, no credit) end the
# job: the account or the network is the problem, not the models.
OUTAGE_STOP_AFTER = 6
_OUTAGE = {"auth", "credit", "unreachable"}
_lock = threading.Lock()


def _vendor(model_id: str) -> str:
    return (model_id or "").split("/", 1)[0]


def selectable(models) -> list:
    """The catalog entries this job tests: the chosen vendors, fixed-price only."""
    out = []
    for m in models or []:
        mid = (m or {}).get("id") or ""
        if _vendor(mid) not in VENDORS:
            continue
        p = m.get("pricing") or {}
        try:
            if float(p.get("prompt") or 0) < 0 or float(p.get("completion") or 0) < 0:
                continue                       # variable price (routers): not one model
        except (TypeError, ValueError):
            continue
        out.append(mid)
    return out


def _reason(r) -> str:
    try:
        msg = ((r.json() or {}).get("error") or {}).get("message") or ""
    except Exception:  # noqa: BLE001 -- not JSON
        msg = r.text or ""
    msg = " ".join(str(msg).split())
    return f"HTTP {r.status_code}" + (f": {msg[:300]}" if msg else "")


def classify(status, why) -> str:
    w = (why or "").lower()
    if "data policy" in w or "zdr" in w:
        return "policy"
    if status in (401, 403):
        return "auth"
    if status == 402:
        return "credit"
    if status == 404:
        return "not_served"
    if status == 429:
        return "rate"
    return "other"


BATCH = {"ok": False, "kind": "batch",
         "why": "batch-only: answers bulk jobs later, not live chat or reports"}


def probe_model(model_id: str, key: str) -> dict:
    """{"ok", "kind", "why"} for one model. Never raises."""
    if (model_id or "").endswith(":batch"):
        return dict(BATCH)                     # 75 of 292 on 2026-10-19: no call needed
    try:
        r = requests.post(CHAT_URL, timeout=TIMEOUT_SEC, allow_redirects=False,
                          headers={"Authorization": f"Bearer {key}"},
                          json={"model": model_id, "max_tokens": 1,
                                "messages": [{"role": "user", "content": "Reply with OK"}]})
        if r.status_code == 200:
            try:
                body = r.json() or {}
            except Exception:  # noqa: BLE001
                body = {}
            if body.get("choices"):
                return {"ok": True, "kind": "ok", "why": ""}
            err = (body.get("error") or {}).get("message") if isinstance(body.get("error"), dict) else ""
            return {"ok": False, "kind": "other", "why": (err or "answered with no choices")[:300]}
        why = _reason(r)
        return {"ok": False, "kind": classify(r.status_code, why), "why": why}
    except Exception as e:  # noqa: BLE001 -- a result, never an error
        return {"ok": False, "kind": "unreachable", "why": f"unreachable ({type(e).__name__})"}


def load() -> dict:
    """{model_id: result} from the last job, or {} -- a missing or broken file is
    "never tested", never an error."""
    try:
        with open(PROBES_PATH) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(results: dict) -> None:
    tmp = PROBES_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(results, f)
    os.replace(tmp, PROBES_PATH)


def _save_progress(results: dict) -> None:
    """Merge into the saved results (other vendors' earlier ones stay). A failed write
    is logged by the caller's next line, never fatal: the job goes on."""
    at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    try:
        _save({**load(), **{k: {**v, "at": v.get("at") or at} for k, v in results.items()}})
    except OSError as e:
        print(f"[CATALOG-TEST] results not saved: {e}", flush=True)


def rank(m) -> int:
    """Picker order: works, untested, refused by the data policy, failed."""
    p = (m or {}).get("probe")
    if not p:
        return 1
    if p.get("ok"):
        return 0
    return 2 if p.get("kind") == "policy" else 3


def run(run_id, key, models, log, done) -> None:
    """The Settings -> Actions job. `log(msg, level)`, `done(status, error, details)`.
    Never raises: anything unexpected ends the run as failed, with the reason."""
    try:
        if not _lock.acquire(blocking=False):
            done("failed", "another catalog test is already running", {})
            return
        try:
            todo = selectable(models)
            if not todo:
                done("completed", None, {"tested": 0})
                log("No models of the tested vendors in the catalog — nothing to test", "warning")
                return
            done("running", None, {"models": len(todo)})
            log(f"Testing {len(todo)} model(s) of {len(VENDORS)} vendor(s): one 1-token call each, no case data")
            started = time.time()
            # The first few, alone: if they are all outages, stop with that one reason.
            head = todo[:OUTAGE_STOP_AFTER]
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                results = dict(zip(head, pool.map(lambda m: probe_model(m, key), head)))
            real = [r for r in results.values() if r["kind"] != "batch"]     # batch: no call made
            if real and all(r["kind"] in _OUTAGE for r in real):
                why = real[0]["why"]
                done("failed", f"stopped: every first call failed the same way — {why}",
                     {"tested": len(results)})
                log(f"Stopped after {len(results)} calls — {why}. The account or the network is "
                    "the problem, not the models; nothing was saved.", "error")
                return
            rest = todo[len(head):]
            with ThreadPoolExecutor(max_workers=WORKERS) as pool:
                for i, (mid, res) in enumerate(zip(rest, pool.map(lambda m: probe_model(m, key), rest)), 1):
                    results[mid] = res
                    if i % 25 == 0:
                        log(f"… {len(results)} of {len(todo)} tested")
                        _save_progress(results)       # the picker marks them as they come
            _save_progress(results)
            counts = {}
            for r in results.values():
                counts[r["kind"]] = counts.get(r["kind"], 0) + 1
            words = {"ok": "work", "policy": "refused by your OpenRouter data policy", "batch": "batch-only",
                     "not_served": "not served", "rate": "rate-limited (try again later)",
                     "credit": "no credit", "auth": "key refused", "unreachable": "unreachable",
                     "other": "failed otherwise"}
            summary = ", ".join(f"{n} {words.get(k, k)}" for k, n in sorted(counts.items(), key=lambda x: -x[1]))
            log(f"Done in {int(time.time() - started)}s: {summary}", "success")
            done("completed", None, {"tested": len(results), "counts": counts})
        finally:
            _lock.release()
    except Exception as e:  # noqa: BLE001 -- the job ends, the backend does not
        try:
            log(f"Catalog test stopped: {type(e).__name__}: {e}", "error")
            done("failed", f"{type(e).__name__}: {e}"[:300], {})
        except Exception:  # noqa: BLE001
            pass
