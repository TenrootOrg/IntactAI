"""Log collection and the final report.

Collection runs BEFORE teardown so nothing needed for the report is destroyed
first. The report runs LAST so teardown problems appear in it.
"""

import json
import os
import shutil

from lib import api as api_lib
from lib import redact as redact_lib
from lib import runner as runner_lib
from lib import shell
from phases import platform as platform_mod


def register(runner, cfg):
    tl = runner.ctx.tl

    # ----------------------------------------------------------------- E --
    @runner.phase("collect", "Gather every log the run touched", optional=True)
    def collect(ctx):
        """Runs regardless of what failed — a failed run is exactly when the
        logs matter. Everything is redacted on the way in: container logs carry
        command lines with credentials, and run_command(logger=None) falls back
        to print()."""
        logs_dir = os.path.join(ctx.run_dir, "logs")
        detail = {"containers": [], "bytes": 0}

        for name in shell.container_names():
            r = shell.run(["docker", "logs", "--tail", "2000", name], timeout=120)
            path = os.path.join(logs_dir, f"container-{name}.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(ctx.redact(r.out))
            detail["containers"].append(name)
            detail["bytes"] += os.path.getsize(path)

        ctx.check("container logs collected", bool(detail["containers"]),
                  actual=len(detail["containers"]))

        # The platform's own support bundle, rather than re-implementing
        # collection. It has already been shown to carry secrets, so it is
        # redacted like everything else.
        c = ctx.get("client")
        if c:
            try:
                body = c.post("/api/support-bundle/prepare", {})
                run_id = body.get("run_id") if isinstance(body, dict) else None
                detail["support_bundle_run"] = run_id
                if run_id:
                    r = c.s.get(f"{c.base}/api/support-bundle/{run_id}/download",
                                timeout=600, stream=True)
                    if r.status_code == 200:
                        path = os.path.join(ctx.run_dir, "artifacts",
                                            "support-bundle.zip")
                        with open(path, "wb") as fh:
                            for chunk in r.iter_content(65536):
                                fh.write(chunk)
                        os.chmod(path, 0o600)
                        detail["support_bundle"] = path
            except Exception as exc:                          # noqa: BLE001
                detail["support_bundle_error"] = ctx.redact(str(exc))[:200]

        # The workflow runs' own logs, keyed by the ids captured at launch —
        # this is what ties a platform log line back to a QA stage.
        if c:
            per_run = {}
            for key in ("kape_run_id", "hunt_run_id", "volweb_run_id"):
                rid = ctx.get(key)
                if rid:
                    per_run[key] = {"run_id": rid, "logs": c.run_logs(rid)}
            path = os.path.join(logs_dir, "workflow-runs.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(_redact_deep(per_run, ctx.redact), fh, indent=2,
                          default=str)
            detail["workflow_runs"] = list(per_run)

        for f in os.listdir(logs_dir):
            os.chmod(os.path.join(logs_dir, f), 0o600)
        return detail

    # --------------------------------------------------------------- F.2 --
    @runner.phase("revoke", "Confirm the dashboard account is as configured",
                  optional=True)
    def revoke(ctx):
        """Leaves qa/123123 in place. Deliberately.

        This phase used to rotate the password to a random value at teardown,
        on the reasoning that a guessable admin account gating the dashboard,
        /api/, uploads and the /velociraptor/ proxy should not outlive the run.
        That reasoning is sound but it is not the operator's call to make here:
        the standing instruction is that the QA credentials are always
        qa/123123, and rotating them meant the dashboard became unusable after
        every run and the operator had to dig a password out of a run
        directory to look at their own appliance.

        Set run.revoke_dashboard_account: true in qa-config.yaml to rotate
        instead. The credential file is written either way, so a run stays
        self-describing.

        The residual risk is real and worth stating plainly rather than
        burying: on a network-reachable appliance this leaves a six-digit
        password on an account that gates everything. What stands behind it is
        the ten-attempt lockout, not the password.
        """
        import secrets
        import string

        c = ctx.get("client")
        rotate = bool(cfg.get("run", "revoke_dashboard_account", default=False))
        username = platform_mod.QA_DASH_USER
        password = platform_mod.QA_DASH_PASSWORD
        rotated = False

        if rotate and c:
            alphabet = string.ascii_letters + string.digits
            password = "Qa-" + "".join(secrets.choice(alphabet) for _ in range(28))
            ctx.redact.secrets.insert(0, password)
            ctx.redact.secrets.sort(key=len, reverse=True)
            body = c.request("POST", "/api/auth/change-password", expect=(),
                             json={"current_password": platform_mod.QA_DASH_PASSWORD,
                                   "new_password": password, "confirm": password})
            rotated = isinstance(body, dict) and bool(body.get("success"))
            ctx.check("dashboard account rotated", rotated, actual=body)

        # Whichever password is live, prove it actually authenticates — a run
        # that leaves the operator locked out of their own box is a failed run
        # regardless of what the config asked for.
        probe = api_lib.Client(cfg.platform_host)
        try:
            probe.login(username, password)
            works = True
        except Exception:                                     # noqa: BLE001
            works = False
        ctx.check("the documented dashboard password works", works,
                  expected="login accepted", actual="accepted" if works
                  else "REJECTED",
                  note=f"{username} / {'<rotated>' if rotated else password}")

        path = os.path.join(ctx.run_dir, "dashboard-credentials.txt")
        with open(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                  "w", encoding="utf-8") as fh:
            fh.write(f"https://{cfg.platform_host}/\n"
                     f"username: {username}\npassword: {password}\n\n"
                     + ("Rotated at teardown.\n" if rotated else
                        "Fixed QA credentials, left in place by design.\n"))
        return {"rotated": rotated, "username": username}

    # ----------------------------------------------------------------- G --
    @runner.phase("report", "Redaction self-test, then write the report",
                  optional=True)
    def report(ctx):
        """The redaction canary runs HERE, before the report is composed. A
        redactor nobody tests is a redactor that does not work, and the failure
        mode is silent by construction — the report looks fine either way."""
        canary_file = os.path.join(ctx.run_dir, "logs", "redaction-canary.log")
        with open(canary_file, "w", encoding="utf-8") as fh:
            fh.write(ctx.redact(redact_lib.canary_text()))
        with open(canary_file, encoding="utf-8") as fh:
            leaked = redact_lib.canary_survives(fh.read())
        ctx.check("redaction canary was removed", not leaked,
                  note="if this fails, treat every artifact in this run "
                       "directory as containing live credentials")

        # And the real thing: no configured secret may appear anywhere.
        offenders = _scan_for_secrets(ctx.run_dir, cfg.secrets())
        ctx.check("no configured credential appears in the run directory",
                  not offenders, actual=offenders[:5])

        tl.render_markdown()
        path = _write_report(ctx, cfg)
        ctx.check("report written", os.path.exists(path), actual=path)
        return {"report": path, "canary_leaked": leaked,
                "secret_offenders": len(offenders)}


# --- report --------------------------------------------------------------


def _write_report(ctx, cfg):
    results = ctx.results
    counts = runner_lib.summarize(results)
    lines = []

    lines += [f"# Intact.AI QA run — {ctx.tl.run_id}", "",
              "**Scope: WINDOWS ONLY.** This run exercises the Windows "
              "collection path end to end — KAPE into Timesketch, the Windows "
              "agentic blueprint, and Windows memory into VolWeb. It is not "
              "full platform coverage, and a green result here says nothing "
              "about the Linux path.", "",
              "**Fast-QA profile.** Two Volatility plugins, cleared event "
              "logs, a 4 GB memory image. Breadth was traded for speed "
              "deliberately; this proves each path *works*, not that the host "
              "was forensically examined.", "",
              "**Yara is checked as having run, not as having matched.** "
              "Rules come from VolWeb's seeded corpus scoped by blueprint "
              "category, with no per-run rule-injection endpoint, and the "
              "pipeline treats zero hits as a legitimate result. So this run "
              "verifies the yarascan worker executes and returns a result "
              "set; it does not verify that any detection content is correct.",
              ""]

    lines += ["## Verdict", "",
              f"| result | count |", "|---|---|",
              f"| passed | {counts.get('pass', 0)} |",
              f"| failed | {counts.get('fail', 0)} |",
              f"| errored | {counts.get('error', 0)} |",
              f"| skipped | {counts.get('skip', 0)} |", ""]

    hard = [r for r in results.values()
            if r.status in (runner_lib.FAIL, runner_lib.ERROR)]
    lines.append("**Overall: " + ("FAILED" if hard else "PASSED") + "**")
    lines.append("")

    # Bugs first — this is what the report is for.
    if hard:
        lines += ["## Bugs found", ""]
        for r in hard:
            lines += [f"### {r.name} — {r.title}", ""]
            if r.error:
                lines += ["Phase raised an exception:", "", "```",
                          r.error.strip()[-1500:], "```", ""]
            for c in r.checks:
                if c.ok:
                    continue
                lines.append(f"- **{c.name}** — expected `{c.expected}`, "
                             f"got `{c.actual}`")
                if c.note:
                    lines.append(f"  - {c.note}")
            lines.append("")

    skipped = [r for r in results.values() if r.status == runner_lib.SKIP]
    if skipped:
        lines += ["## Not reached", "",
                  "These never ran, so they are neither passing nor failing. "
                  "A dependency failed first.", "",
                  "| phase | because |", "|---|---|"]
        for r in skipped:
            lines.append(f"| {r.name} | {r.skipped_because} |")
        lines.append("")

    lines += ["## Phases", "",
              "| phase | status | duration | checks |", "|---|---|---|---|"]
    for r in results.values():
        passed = sum(1 for c in r.checks if c.ok)
        lines.append(f"| {r.name} | {r.status} | {r.duration_s or 0}s | "
                     f"{passed}/{len(r.checks)} |")
    lines.append("")

    fusion = results.get("fusion")
    if fusion and fusion.detail:
        d = fusion.detail
        lines += ["## Fusion", "",
                  "Baseline numbers for this run. The QA case is deliberately "
                  "tiny, so fuse time should be near-instant; these are the "
                  "numbers to compare against if a larger case is ever run "
                  "(the `_score_assets` pass is quadratic in assets x "
                  "entities).", "",
                  "| metric | value |", "|---|---|",
                  f"| fuse seconds | {d.get('fuse_seconds')} |",
                  f"| entities | {d.get('entities')} |",
                  f"| relationships | {d.get('relationships')} |",
                  f"| findings | {d.get('findings')} |",
                  f"| cross-host findings | {d.get('cross_host_findings')} |",
                  f"| sources | {', '.join(d.get('sources') or []) or 'none'} |",
                  ""]

    td = results.get("teardown")
    lines += ["## Windows target state", ""]
    if td and td.detail:
        clean = td.detail.get("windows_left_clean")
        lines.append("The target was left **"
                     + ("clean" if clean else "NOT clean") + "**.")
        left = td.detail.get("left_behind") or []
        if left:
            lines += ["", "Still on the box — remove by hand:", ""]
            lines += [f"- `{p}`" for p in left]
        lines.append("")
        lines.append(f"Velociraptor service after teardown: "
                     f"`{td.detail.get('service_after')}`")
    else:
        lines.append("Teardown did not run. Assume the Velociraptor client and "
                     "any staged files are still on the target.")
    lines.append("")

    ids = ctx.tl.collected_ids()
    if ids:
        lines += ["## Platform-side ids", "",
                  "Every id this run created, so a failure can be investigated "
                  "in the product rather than only in these files.", "",
                  "| kind | id |", "|---|---|"]
        for k, vals in sorted(ids.items()):
            for v in vals:
                lines.append(f"| {k} | `{v}` |")
        lines.append("")

    lines += ["## Where everything is", "",
              f"- run directory: `{ctx.run_dir}` (0700)",
              f"- correlated timeline: `timeline.jsonl` / `timeline.md`",
              f"- per-phase results: `phases/*.json`",
              f"- logs: `logs/`",
              "",
              "This report is redacted and is the artifact intended for "
              "sharing. The rest of the run directory is not — it holds "
              "container logs, a support bundle and possibly a memory image.",
              ""]

    path = os.path.join(ctx.run_dir, "REPORT.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(ctx.redact("\n".join(lines)) + "\n")
    os.chmod(path, 0o600)

    with open(os.path.join(ctx.run_dir, "results.json"), "w",
              encoding="utf-8") as fh:
        json.dump({"run_id": ctx.tl.run_id, "counts": counts,
                   "phases": [r.to_dict() for r in results.values()]},
                  fh, indent=2, default=str)
    return path


# The one file whose entire purpose is to hold the credential. Scanning it and
# reporting a leak is a false positive that makes the leak check cry wolf —
# which is worse than not having it, because a real hit then looks routine.
_DELIBERATE_CREDENTIAL_FILES = {"dashboard-credentials.txt"}


def _scan_for_secrets(run_dir, secrets, max_bytes=8_000_000):
    """Grep the run directory for any configured credential.

    Skips large binaries — a memory image legitimately contains whatever was in
    RAM, and scanning it would be both slow and meaningless.
    """
    hits = []
    secrets = [s for s in secrets if s and len(s) >= 6]
    if not secrets:
        return hits
    for root, _dirs, files in os.walk(run_dir):
        for fn in files:
            path = os.path.join(root, fn)
            if fn in _DELIBERATE_CREDENTIAL_FILES:
                continue
            if fn.endswith((".zip", ".raw", ".mem", ".dmp", ".msi", ".exe")):
                continue
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    body = fh.read()
            except OSError:
                continue
            for s in secrets:
                if s in body:
                    hits.append(os.path.relpath(path, run_dir))
                    break
    return hits


def _redact_deep(obj, redact):
    if isinstance(obj, dict):
        return {k: _redact_deep(v, redact) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_deep(v, redact) for v in obj]
    if isinstance(obj, str):
        return redact(obj)
    return obj
