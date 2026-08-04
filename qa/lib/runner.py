"""Phase registry and execution.

Two rules shape this:

CONTINUE ON FAILURE. A QA run that stops at the first problem surfaces one bug
per hour-long run. This one records the failure and keeps going, so a single
run surfaces everything it can reach.

BUT NOT BLINDLY. "Keep going" is wrong when a phase's inputs do not exist —
running the VolWeb stage with no enrolled client produces a confusing second
failure that buries the real one. So phases declare `needs`, and a phase whose
dependency failed is SKIPPED, not run. The report then distinguishes "this
broke" from "this never got a chance", which is the difference between a bug
list and a wall of noise.

Assertion helpers live here too. `check()` records a named assertion and its
evidence rather than raising, because "phase 6 failed" is useless next to
"phase 6: yara matched 0 rules, expected >=1".
"""

import json
import os
import time
import traceback

PASS = "pass"
FAIL = "fail"
SKIP = "skip"
ERROR = "error"          # phase raised, as opposed to asserting false


class Check:
    """One named assertion inside a phase, with the evidence attached."""

    def __init__(self, name, ok, expected=None, actual=None, note=None):
        self.name, self.ok = name, bool(ok)
        self.expected, self.actual, self.note = expected, actual, note

    def to_dict(self):
        d = {"name": self.name, "ok": self.ok}
        for k in ("expected", "actual", "note"):
            v = getattr(self, k)
            if v is not None:
                d[k] = v
        return d


class PhaseContext:
    """What a phase is handed. Everything it needs, nothing global."""

    def __init__(self, cfg, tl, run_dir, results, redactor):
        self.cfg = cfg
        self.tl = tl
        self.run_dir = run_dir
        self.results = results          # name -> PhaseResult, for reading deps
        self.redact = redactor
        self.data = {}                  # cross-phase values (client_id, case_id…)
        self._checks = []

    # --- assertions ------------------------------------------------------

    def check(self, name, ok, expected=None, actual=None, note=None):
        c = Check(name, ok, expected, actual, note)
        self._checks.append(c)
        self.tl.event("check", status="ok" if c.ok else "fail",
                      detail={"check": name, "expected": expected,
                              "actual": actual, "note": note})
        return c.ok

    def take_checks(self):
        out, self._checks = self._checks, []
        return out

    # --- shared state ----------------------------------------------------

    def set(self, **kw):
        """Store a value for later phases AND record it on the timeline if it
        looks like a platform-side id — those are what make a run traceable."""
        self.data.update(kw)
        ids = {k: v for k, v in kw.items()
               if isinstance(v, str) and k.endswith(("_id", "_ids"))}
        if ids:
            self.tl.ids(**ids)

    def get(self, key, default=None):
        return self.data.get(key, default)


class PhaseResult:
    def __init__(self, name, title):
        self.name, self.title = name, title
        self.status = None
        self.checks = []
        self.detail = {}
        self.error = None
        self.started = None
        self.duration_s = None
        self.skipped_because = None

    @property
    def ok(self):
        return self.status == PASS

    def to_dict(self):
        return {
            "phase": self.name,
            "title": self.title,
            "status": self.status,
            "duration_s": self.duration_s,
            "checks": [c.to_dict() for c in self.checks],
            "failed_checks": [c.to_dict() for c in self.checks if not c.ok],
            "detail": self.detail,
            "error": self.error,
            "skipped_because": self.skipped_because,
        }


class Runner:
    def __init__(self, ctx):
        self.ctx = ctx
        self.phases = []

    def phase(self, name, title, needs=(), critical=False, optional=False):
        """Register a phase.

        critical — a failure here aborts the run. Reserved for the phases that
                   make everything after them meaningless (preflight, install).
                   Everything else records and continues.
        optional — a failure is reported but does not mark the run failed. For
                   things that are nice to have (an LLM summary with no key
                   configured) rather than product behaviour under test.
        """
        def register(fn):
            self.phases.append({
                "name": name, "title": title, "fn": fn,
                "needs": tuple(needs), "critical": critical,
                "optional": optional})
            return fn
        return register

    # A dependency the OPERATOR skipped is treated as satisfied. `--skip
    # install` means "this box is already installed, get on with it" — the
    # alternative is that skipping one early phase cascades into skipping
    # everything, which makes iterating on a late phase cost a full reinstall
    # per attempt. A dependency that ran and FAILED still blocks, which is the
    # case that actually protects the report from cascade noise.
    _OPERATOR_SKIPS = ("explicitly skipped", "not selected")

    def _unmet(self, needs):
        for dep in needs:
            res = self.ctx.results.get(dep)
            if res is None:
                return f"{dep} did not run"
            if res.status in (FAIL, ERROR):
                return f"{dep} {res.status}ed"
            if res.status == SKIP and res.skipped_because not in self._OPERATOR_SKIPS:
                return f"{dep} was skipped ({res.skipped_because})"
        return None

    def run(self, only=None, skip=None):
        tl = self.ctx.tl
        aborted = False

        for spec in self.phases:
            name = spec["name"]
            res = PhaseResult(name, spec["title"])
            self.ctx.results[name] = res

            if only and name not in only:
                res.status, res.skipped_because = SKIP, "not selected"
                continue
            if skip and name in skip:
                res.status, res.skipped_because = SKIP, "explicitly skipped"
                tl.warn("phase_skipped", stage=name, detail="requested by operator")
                continue
            if aborted:
                res.status, res.skipped_because = SKIP, "run aborted earlier"
                continue

            unmet = self._unmet(spec["needs"])
            if unmet:
                res.status, res.skipped_because = SKIP, unmet
                tl.warn("phase_skipped", stage=name, detail={"because": unmet})
                continue

            tl.stage(name)
            res.started = time.time()
            self.ctx.take_checks()          # no leakage from a previous phase

            try:
                detail = spec["fn"](self.ctx) or {}
                res.detail = detail if isinstance(detail, dict) else {"result": detail}
                res.checks = self.ctx.take_checks()
                failed = [c for c in res.checks if not c.ok]
                res.status = FAIL if failed else PASS
                if failed:
                    tl.fail("phase_failed", stage=name, detail={
                        "failed_checks": [c.name for c in failed]})
                else:
                    tl.ok("phase_passed", stage=name,
                          detail={"checks": len(res.checks)})
            except Exception as exc:                     # noqa: BLE001
                res.checks = self.ctx.take_checks()
                res.status = ERROR
                res.error = self.ctx.redact(
                    "".join(traceback.format_exception(exc))[-4000:])
                tl.fail("phase_error", stage=name,
                        detail={"error": self.ctx.redact(str(exc))[:400]})
            finally:
                res.duration_s = round(time.time() - res.started, 1)
                self._persist(res)

            if spec["critical"] and not res.ok:
                aborted = True
                tl.fail("run_aborted", stage=name, detail={
                    "because": f"{name} is critical and did not pass"})

        return self.ctx.results

    def _persist(self, res):
        """Write each phase result as it completes, not at the end. A run that
        is killed mid-way must still leave behind what it learned."""
        path = os.path.join(self.ctx.run_dir, "phases", f"{res.name}.json")
        payload = _redact(res.to_dict(), self.ctx.redact)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)


def _redact(obj, redact):
    if isinstance(obj, dict):
        return {k: _redact(v, redact) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact(v, redact) for v in obj]
    if isinstance(obj, str):
        return redact(obj)
    return obj


def summarize(results):
    counts = {PASS: 0, FAIL: 0, SKIP: 0, ERROR: 0}
    for r in results.values():
        counts[r.status] = counts.get(r.status, 0) + 1
    return counts
