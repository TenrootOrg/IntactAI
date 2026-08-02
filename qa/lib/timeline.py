"""The single correlated log for a QA run.

The requirement this satisfies: today an install log, a Velociraptor hunt, a
Timesketch task and a VolWeb job have nothing linking them, so reconstructing
"what was happening at 14:32" is manual archaeology across four systems. A run
mints one id and threads it through everything, and every platform-side id
(flow, hunt, run, sketch, case) is captured AT LAUNCH and written here — so a
line in a container log can always be traced back to the QA stage that caused
it, and vice versa.

Two renderings, one source:
  timeline.jsonl  append-only, one object per event, machine-readable
  timeline.md     generated from the JSONL, never hand-written

Generated rather than maintained in parallel because two hand-written logs
always drift, and the one that drifts is always the one you are reading at 3am.

Waits log what they are waiting on and for how long. A harness that prints
nothing for 20 minutes is indistinguishable from a hung one.
"""

import json
import os
import sys
import threading
import time
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc)


def _iso(dt=None):
    return (dt or _now()).isoformat(timespec="milliseconds")


class Timeline:
    def __init__(self, run_dir, run_id, redactor=None):
        self.run_dir = run_dir
        self.run_id = run_id
        self.redact = redactor or (lambda s: s)
        self.jsonl = os.path.join(run_dir, "timeline.jsonl")
        self.started = _now()
        self._lock = threading.Lock()
        self._stage = "init"

    # --- writing ---------------------------------------------------------

    def event(self, event, status="info", stage=None, ids=None, detail=None, **extra):
        """Append one event. Everything here is redacted on the way in, not on
        the way out — an unredacted secret written to disk has already leaked,
        regardless of what the report does with it later."""
        rec = {
            "ts": _iso(),
            "elapsed_s": round((_now() - self.started).total_seconds(), 1),
            "run_id": self.run_id,
            "stage": stage or self._stage,
            "event": event,
            "status": status,
        }
        if ids:
            rec["ids"] = ids
        if detail is not None:
            rec["detail"] = detail
        if extra:
            rec.update(extra)

        rec = _redact_structure(rec, self.redact)

        line = json.dumps(rec, default=str, ensure_ascii=False)
        with self._lock:
            with open(self.jsonl, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())     # a crashed run must still have its log
        self._echo(rec)
        return rec

    def stage(self, name):
        self._stage = name
        self.event("stage_begin", stage=name)
        return name

    def ok(self, event, **kw):
        return self.event(event, status="ok", **kw)

    def warn(self, event, **kw):
        return self.event(event, status="warning", **kw)

    def fail(self, event, **kw):
        return self.event(event, status="fail", **kw)

    def ids(self, **kw):
        """Record platform-side identifiers the moment they are known.

        Called at LAUNCH rather than at completion on purpose: if a flow hangs
        or the harness dies, the id is what lets an operator go and look at it
        in the product. Recording it only on success loses it in exactly the
        case where it matters.
        """
        return self.event("ids", ids={k: v for k, v in kw.items() if v})

    # --- waiting ---------------------------------------------------------

    def wait(self, what, timeout_s, poll_s, probe, describe=None, heartbeat_s=60):
        """Poll `probe()` until it returns something truthy.

        Returns (value, elapsed_seconds) or (None, elapsed) on timeout. Logs a
        heartbeat so a long wait is visibly a wait rather than a hang, and logs
        the timeout as a first-class event so the report can say "waited 45m
        for X" instead of just "X failed".
        """
        t0 = time.monotonic()
        self.event("wait_begin", detail={"what": what, "timeout_s": timeout_s})
        last_beat = t0
        while True:
            try:
                value = probe()
            except Exception as exc:                      # noqa: BLE001
                # A probe that raises is a probe that could not answer, not a
                # negative answer. Keep waiting, but say so — a permanently
                # failing probe otherwise looks identical to "not ready yet".
                self.warn("wait_probe_error",
                          detail={"what": what, "error": str(exc)[:300]})
                value = None

            if value:
                elapsed = time.monotonic() - t0
                self.ok("wait_done", detail={
                    "what": what, "waited_s": round(elapsed, 1),
                    "state": describe(value) if describe else None})
                return value, elapsed

            elapsed = time.monotonic() - t0
            if elapsed >= timeout_s:
                self.fail("wait_timeout", detail={
                    "what": what, "waited_s": round(elapsed, 1),
                    "timeout_s": timeout_s})
                return None, elapsed

            if time.monotonic() - last_beat >= heartbeat_s:
                last_beat = time.monotonic()
                self.event("wait_heartbeat", detail={
                    "what": what,
                    "waited_s": round(elapsed),
                    "remaining_s": round(timeout_s - elapsed)})

            time.sleep(poll_s)

    # --- console ---------------------------------------------------------

    def _echo(self, rec):
        mark = {"ok": "✓", "fail": "✗", "warning": "!",
                "info": "·"}.get(rec["status"], "·")
        stage = rec["stage"]
        line = f"[{rec['elapsed_s']:>7.1f}s] {mark} {stage:<22} {rec['event']}"
        detail = rec.get("detail")
        if isinstance(detail, dict):
            bits = [f"{k}={v}" for k, v in list(detail.items())[:4]
                    if not isinstance(v, (dict, list))]
            if bits:
                line += "  " + " ".join(bits)
        elif isinstance(detail, str):
            line += "  " + detail[:120].replace("\n", " ")
        if rec.get("ids"):
            line += "  " + " ".join(f"{k}={v}" for k, v in rec["ids"].items())
        print(line, flush=True)

    # --- rendering -------------------------------------------------------

    def read(self):
        if not os.path.exists(self.jsonl):
            return []
        out = []
        with open(self.jsonl, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass          # a torn final line from a killed run
        return out

    def render_markdown(self, path=None):
        path = path or os.path.join(self.run_dir, "timeline.md")
        events = self.read()
        rows = ["# QA timeline — " + self.run_id, ""]

        gaps = _long_gaps(events)
        if gaps:
            rows += ["## Longest gaps", "",
                     "Where the run actually spent its time. A gap is a wait, "
                     "or a hang — the timeline cannot tell them apart, but it "
                     "can tell you where to look.", "",
                     "| gap | after | stage |", "|---|---|---|"]
            for secs, ev in gaps[:5]:
                rows.append(f"| {secs/60:.1f} min | {ev['event']} | {ev['stage']} |")
            rows.append("")

        rows += ["## Events", "",
                 "| elapsed | stage | event | status | detail |",
                 "|---|---|---|---|---|"]
        for e in events:
            detail = e.get("detail")
            if isinstance(detail, dict):
                detail = ", ".join(f"{k}={v}" for k, v in detail.items()
                                   if not isinstance(v, (dict, list)))
            detail = str(detail or "").replace("|", "\\|")[:200]
            ids = " ".join(f"`{k}={v}`" for k, v in (e.get("ids") or {}).items())
            rows.append(f"| {e['elapsed_s']}s | {e['stage']} | {e['event']} "
                        f"{ids} | {e['status']} | {detail} |")

        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(rows) + "\n")
        return path

    def collected_ids(self):
        """Every platform-side id the run captured, merged. This is what makes
        a failed run investigable in the product rather than only in these
        files."""
        merged = {}
        for e in self.read():
            for k, v in (e.get("ids") or {}).items():
                merged.setdefault(k, [])
                if v not in merged[k]:
                    merged[k].append(v)
        return merged


def _long_gaps(events, threshold_s=30):
    gaps = []
    for prev, nxt in zip(events, events[1:]):
        delta = nxt["elapsed_s"] - prev["elapsed_s"]
        if delta >= threshold_s:
            gaps.append((delta, prev))
    return sorted(gaps, key=lambda g: g[0], reverse=True)


def _redact_structure(obj, redact):
    if isinstance(obj, dict):
        return {k: _redact_structure(v, redact) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_structure(v, redact) for v in obj]
    if isinstance(obj, str):
        return redact(obj)
    return obj


def new_run(cfg, run_id=None):
    """Create the run directory and return (run_dir, run_id).

    0700 because the directory is about to hold container logs, a support
    bundle and possibly a memory image.
    """
    run_id = run_id or "qa-" + _now().strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(cfg.output_dir, run_id)
    os.makedirs(run_dir, mode=0o700, exist_ok=True)
    os.chmod(run_dir, 0o700)
    for sub in ("logs", "artifacts", "phases"):
        d = os.path.join(run_dir, sub)
        os.makedirs(d, mode=0o700, exist_ok=True)
    return run_dir, run_id
