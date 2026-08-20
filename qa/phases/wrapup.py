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
    @runner.phase("collect", "Gather every log the run touched", always=True)
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

        # THE STATE OF THE DAEMON, not just what its containers said. An
        # install once failed with `No such image: nginx:1.31.3-alpine` one
        # line after logging that exact image as loaded, and none of the
        # container logs could explain it -- the daemon had been restarted
        # onto a different data-root mid-install and the whole image store
        # went with it. `docker info` says that in one line; without it the
        # diagnosis took an hour of reading installer source. Best-effort by
        # design: a box too broken to answer is itself the finding, and must
        # not cost us the logs we already have.
        for name, argv in (
                ("docker-images", ["docker", "images", "--digests"]),
                ("docker-ps-all", ["docker", "ps", "-a", "--no-trunc"]),
                ("docker-info", ["docker", "info"]),
                ("disk-free", ["df", "-h"])):
            try:
                r = shell.run(argv, timeout=60)
                path = os.path.join(logs_dir, f"{name}.txt")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write(ctx.redact(r.out or ""))
                if name == "docker-info":
                    root = [l.split(":", 1)[1].strip()
                            for l in (r.out or "").splitlines()
                            if l.strip().startswith("Docker Root Dir:")]
                    detail["docker_root"] = root[0] if root else "unknown"
            except Exception as exc:                          # noqa: BLE001
                detail[f"{name}_error"] = ctx.redact(str(exc))[:200]

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
    @runner.phase("revoke", "Confirm the dashboard account is as configured",)
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
                  always=True)
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

        # Everything the harness writes goes through ctx.redact on the way in.
        # The engine's own logs do not: run_bootstrap and run_cli pass `--log
        # <path>` INTO the run directory, so the product writes there directly
        # and the redactor never sees a byte of it. That is how a configured
        # credential reached an uploaded artifact while every harness-written
        # file was clean -- and this repo is public. So sweep the directory
        # before scanning it, rather than reporting a leak that was ours to
        # prevent.
        detail_redacted = _redact_run_directory(ctx)

        # And the real thing: no configured secret may appear anywhere.
        offenders = _scan_for_secrets(ctx.run_dir, cfg.secrets())
        # NAMED, not counted. This check fired for real and the timeline line
        # carried no `actual` at all, because a list value rendered as nothing
        # -- so the one check whose entire job is to say a credential leaked
        # could not say where. A leak you cannot locate is a leak you cannot
        # fix.
        ctx.check("no configured credential appears in the run directory",
                  not offenders,
                  expected="no run artifact contains a configured secret",
                  actual=(", ".join(offenders[:5])
                          + (f" (+{len(offenders) - 5} more)"
                             if len(offenders) > 5 else ""))
                         if offenders else "clean",
                  note="these files are uploaded as build artifacts; treat "
                       "every credential named in qa-config.yaml as exposed "
                       "until this passes")

        tl.render_markdown()
        path = _write_report(ctx, cfg)
        ctx.check("report written", os.path.exists(path), actual=path)
        return {"report": path, "canary_leaked": leaked,
                "secret_offenders": len(offenders),
                "files_redacted": detail_redacted}


# --- report --------------------------------------------------------------


def _feature_sweep_section(lines, results):
    """What the backend HTTP sweep found, including what it deliberately did not.

    The skip list is not padding. A reader who sees "142 passed" and no mention
    of AWS will reasonably assume AWS was covered; naming every endpoint that
    was not called, and why, is the difference between a report and an advert.
    """
    fr = results.get("features")
    if not fr or not fr.detail:
        return
    d = fr.detail

    lines += ["## Feature sweep", ""]

    rows = []
    for tier, label in (("tier0", "Tier 0 — read-only smoke"),
                        ("tier1", "Tier 1 — create/read/delete round-trips"),
                        ("tier2", "Tier 2 — needs an enrolled client")):
        entries = d.get(tier) or {}
        if entries:
            rows.append(f"| {label} | {len(entries)} |")
    if rows:
        lines += ["| tier | endpoints exercised |", "|---|---|"] + rows + [""]

    caps = d.get("containers") or {}
    if caps:
        lines += ["Containers the platform reported, which is what the sweep "
                  "used to decide what to skip:", "",
                  "| service | state |", "|---|---|"]
        lines += [f"| {k} | {v} |" for k, v in sorted(caps.items())]
        lines.append("")

    skipped = d.get("skipped") or []
    if skipped:
        lines += ["### Not tested, and why", "",
                  "Each of these needs something this box does not have. They "
                  "are listed so a green run is never mistaken for full "
                  "coverage.", "",
                  "| endpoint | reason |", "|---|---|"]
        for item in skipped:
            lines.append(f"| `{item.get('path')}` | {item.get('reason')} |")
        lines.append("")


def _pipelines_section(lines, results):
    """Which of the product's lightweight blueprints actually ran.

    Separate from the feature sweep because it answers a different question.
    The sweep says the API responds; this says a collection was dispatched to a
    real client, a detection engine ran over real evidence, an artefact was
    built. The skip list matters just as much -- a reader must be able to see at
    a glance that the Windows pipelines did not run and why.
    """
    pr = results.get("pipelines")
    if not pr or not pr.detail:
        return
    d = pr.detail

    lines += ["## Pipelines", ""]

    ran = d.get("ran") or {}
    if ran:
        lines += ["| pipeline | blueprint | result |", "|---|---|---|"]
        for name, info in sorted(ran.items()):
            bits = []
            if info.get("events") is not None:
                bits.append(f"{info['events']:,} plaso event(s)")
            if info.get("sketch_id"):
                bits.append(f"sketch {info['sketch_id']}")
            if info.get("entities") is not None:
                bits.append(f"{info['entities']} entities / "
                            f"{info.get('relationships')} relationships")
            if info.get("findings") is not None and "entities" not in info:
                bits.append(f"{info['findings']} finding(s)")
            if info.get("rows") is not None:
                bits.append(f"{info['rows']} row(s)")
            if info.get("plugins_ok"):
                bits.append("plugins: " + ", ".join(info["plugins_ok"][:5]))
            if info.get("bytes"):
                bits.append(f"{info['bytes'] / 2**20:.1f} MB")
            if info.get("client_id"):
                bits.append(f"client {info['client_id']}")
            # Where the evidence came from is the single most important thing a
            # reader needs: "real host logs" and "a canned sample" are very
            # different claims, and only one of them is being made here.
            if info.get("evidence"):
                bits.append(f"from {info['evidence']}")
            lines.append(f"| {name} | `{info.get('blueprint', '-')}` | "
                         f"{', '.join(bits) or 'completed'} |")
        lines.append("")

    skipped = d.get("skipped") or []
    if skipped:
        lines += ["### Pipelines that did not run, and why", "",
                  "| pipeline | blueprint | reason |", "|---|---|---|"]
        for item in skipped:
            lines.append(f"| {item.get('pipeline')} | "
                         f"`{item.get('blueprint', '-')}` | {item.get('reason')} |")
        lines.append("")


def _provenance_section(lines, ctx, cfg):
    """Which code and which images this result actually describes.

    The appliance takes its service images from a published RELEASE, never from
    the checkout (lib/modules/backend.sh refuses to rebuild). So a run on a
    branch tests that branch's installer, libraries, compose files and pins
    against somebody else's containers unless the workflow built them. Without
    this section a green result reads as "this branch works", which is a
    stronger claim than the run supports.
    """
    import os

    lines += ["## Provenance", "",
              "| what | value |", "|---|---|"]
    for label, value in (
        ("ref", os.environ.get("QA_REF") or "(not recorded)"),
        ("commit", os.environ.get("QA_COMMIT") or "(not recorded)"),
        ("appliance tree", cfg.repo_dir or "(default)"),
        ("install mode",
         "air-gap (--package)" if os.environ.get("QA_INSTALL_PACKAGE_DIR")
         else "online"),
        ("images from release", os.environ.get("QA_IMAGES_TAG") or "(the VERSION file)"),
        ("images built from this ref", os.environ.get("QA_BUILT_IMAGES") or "none"),
        ("backend under test", os.environ.get("QA_BACKEND_IMAGE") or "release"),
    ):
        lines.append(f"| {label} | `{value}` |")

    built = (os.environ.get("QA_BUILT_IMAGES") or "").strip()

    # MEASURED, not assumed. This block used to state that a built image meant
    # "engine and container match", on the strength of the workflow having
    # built one and pinned config.yaml to it. It does not follow: when a
    # release package ships a backend image, lib/config.sh deliberately
    # overrides the pin with the package's tag ("THE PACKAGE WINS OVER THE
    # PIN", to stop a stale pin triggering a source rebuild) and the freshly
    # built image is never deployed. Every run so far reported that engine and
    # container matched while running the release's backend -- a report
    # claiming coverage it does not have is worse than one that admits the
    # gap, so ask the daemon what is actually running.
    running = ""
    try:
        r = shell.run(["docker", "inspect", "--format", "{{.Config.Image}}",
                       "intact_backend"], timeout=30)
        running = (r.out or "").strip().splitlines()[0] if (r.out or "").strip() else ""
    except Exception:                                         # noqa: BLE001
        running = ""
    lines.append(f"| backend image actually running | `{running or 'unknown'}`|")

    if not built:
        verdict = ("**No image was rebuilt from this ref**, so this run pairs "
                   "this ref's engine with the release's containers — a "
                   "combination no customer runs, since an install or upgrade "
                   "always brings both from the same release.")
    elif running and running in built:
        verdict = (f"`{running}` was rebuilt from this ref and is the image "
                   f"actually running, so engine and container match.")
    elif running and _scenario_upgrades():
        verdict = (f"`{running}` is running, not the `{built}` built here — "
                   f"which is correct for an upgrade scenario. Upgrading to a "
                   f"release means ending on that release's backend; what this "
                   f"ref supplies is the ENGINE that performed the upgrade, "
                   f"together with the installer and compose files.")
    elif running:
        verdict = (f"**The image built from this ref was not used.** "
                   f"`{built}` was built and pinned, but `{running}` is what "
                   f"is running: a release package ships its own backend "
                   f"image and lib/config.sh corrects the pin to the "
                   f"package's tag. This run therefore tested the RELEASE's "
                   f"backend against this ref's engine, installer and compose "
                   f"files — not this ref's backend code.")
    else:
        verdict = (f"`{built}` was built from this ref, but the running "
                   f"backend image could not be read, so whether it was "
                   f"actually used is unknown.")
    lines += ["", "Service images come from the release named above. " + verdict, ""]


def _write_report(ctx, cfg):
    results = ctx.results
    counts = runner_lib.summarize(results)
    lines = []

    # The scope banner is derived, never assumed. It used to be a hard-coded
    # "WINDOWS ONLY", which on a Linux-only run described a machine that was
    # never part of it -- and the scope banner is the one paragraph a reader
    # trusts to tell them what a green result is worth.
    lines += [f"# Intact.AI QA run — {ctx.tl.run_id}", ""]

    if cfg.windows_enabled:
        lines += ["**Scope: WINDOWS ONLY.** This run exercises the Windows "
                  "collection path end to end — KAPE into Timesketch, the "
                  "Windows agentic blueprint, and Windows memory into VolWeb. "
                  "It is not full platform coverage, and a green result here "
                  "says nothing about the Linux path.", "",
                  "**Fast-QA profile.** Two Volatility plugins, cleared event "
                  "logs, a 4 GB memory image. Breadth was traded for speed "
                  "deliberately; this proves each path *works*, not that the "
                  "host was forensically examined.", "",
                  "**Yara is checked as having run, not as having matched.** "
                  "Rules come from VolWeb's seeded corpus scoped by blueprint "
                  "category, with no per-run rule-injection endpoint, and the "
                  "pipeline treats zero hits as a legitimate result. So this "
                  "run verifies the yarascan worker executes and returns a "
                  "result set; it does not verify that any detection content "
                  "is correct.", ""]
    else:
        lines += ["**Scope: LINUX ONLY — no Windows endpoint took part.** "
                  "Install, hardening and the backend HTTP surface are "
                  "exercised, and the Velociraptor Linux client is enrolled on "
                  "the appliance itself. Everything Windows-specific — KAPE "
                  "into Timesketch, the Windows agentic blueprint, Windows "
                  "memory into VolWeb — did not run and is listed under *Not "
                  "reached*. A green result here says nothing about the "
                  "Windows path, which is how most customers use the product.",
                  "",
                  "**The client is the appliance.** Collection is proven to "
                  "*dispatch and complete*, not to find anything: a Linux "
                  "appliance host is not a compromised workstation and will "
                  "not produce the findings a customer's endpoint would.", ""]

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

    _feature_sweep_section(lines, results)
    _pipelines_section(lines, results)
    _provenance_section(lines, ctx, cfg)

    # "Windows target state" only when there WAS a Windows target. A section
    # reading "assume the client is still on the target" is actively misleading
    # about a machine that never existed.
    if cfg.windows_enabled:
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
            lines.append("Teardown did not run. Assume the Velociraptor client "
                         "and any staged files are still on the target.")
        lines.append("")
    else:
        tdl = results.get("teardown_linux")
        if tdl:
            lines += ["## Appliance-hosted client", ""]
            lines.append("The Velociraptor Linux client was installed on the "
                         "appliance itself and "
                         + ("removed again."
                            if tdl.status == "pass"
                            else "**may still be running** — check "
                                 "`systemctl status intact-qa-velociraptor`."))
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


def _scenario_upgrades():
    """Whether this run performed an upgrade, per the shared catalogue.

    Read from scenarios.py rather than a second env var: the workflow already
    derives everything else from that table, and a duplicate would be one more
    thing to drift.
    """
    try:
        import scenarios
        return bool(scenarios.route_for(os.environ.get("QA_SCENARIO") or ""))
    except Exception:                                         # noqa: BLE001
        return False


def _redact_run_directory(ctx, max_bytes=8_000_000):
    """Rewrite every text artifact in the run directory through the redactor.

    Only files the harness did not already redact can change here, so this is
    idempotent and cheap. Binaries and oversized files are left alone: a memory
    image legitimately contains whatever was in RAM, and rewriting it would be
    both meaningless and slow.

    The credential file is skipped for the same reason the scanner skips it --
    holding the credential is its entire purpose.
    """
    changed = 0
    for root, _dirs, files in os.walk(ctx.run_dir):
        for fn in files:
            if fn in _DELIBERATE_CREDENTIAL_FILES:
                continue
            if fn.endswith((".zip", ".raw", ".mem", ".dmp", ".msi", ".exe",
                            ".tar", ".gz", ".png", ".jpg")):
                continue
            path = os.path.join(root, fn)
            try:
                if os.path.getsize(path) > max_bytes:
                    continue
                with open(path, encoding="utf-8", errors="replace") as fh:
                    body = fh.read()
            except OSError:
                continue
            clean = ctx.redact(body)
            if clean != body:
                try:
                    with open(path, "w", encoding="utf-8") as fh:
                        fh.write(clean)
                    os.chmod(path, 0o600)
                    changed += 1
                except OSError:
                    continue
    return changed


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
