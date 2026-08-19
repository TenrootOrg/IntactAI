#!/usr/bin/env python3
"""End-to-end QA for Intact.AI: install, drive, assert, tear down, report.

One command from a box with nothing installed to a finished report. No pauses,
no "now go and run this on the Windows machine".

    python3 qa/run_qa.py                     # everything
    python3 qa/run_qa.py --skip wipe,install # against the box as it stands
    python3 qa/run_qa.py --only preflight    # just check the prerequisites

Credentials come from qa/qa-config.yaml (tracked, blanked on commit) or the
matching QA_* environment variables. Nothing is prompted for and nothing is
passed in argv.

THE HARNESS CANNOT LIVE IN THE TREE IT DELETES. The `wipe` phase removes
/home/tenroot/intact, and qa/ is inside it. So unless --skip wipe is given,
this re-executes itself from a copy outside the repo before touching anything.
That also makes the run honest: the harness verifying the clone is not the copy
that came from the clone, so a broken commit cannot ship a harness that passes
itself.
"""

import argparse
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from lib import config as qa_config      # noqa: E402
from lib import redact as qa_redact      # noqa: E402
from lib import runner as runner_lib     # noqa: E402
from lib import timeline as timeline_lib # noqa: E402

RUNNER_HOME = os.path.expanduser("~/.qa-runner")


def _self_copy_and_exec(argv, run_id):
    """Copy qa/ out of the repo and re-exec from there."""
    dest = os.path.join(RUNNER_HOME, run_id)
    if os.path.exists(dest):
        shutil.rmtree(dest)
    os.makedirs(RUNNER_HOME, mode=0o700, exist_ok=True)
    shutil.copytree(HERE, dest)
    os.chmod(dest, 0o700)
    # qa-config.yaml comes along with the copy and carries the sudo password.
    cfg_copy = os.path.join(dest, "qa-config.yaml")
    if os.path.exists(cfg_copy):
        os.chmod(cfg_copy, 0o600)

    print(f"Harness copied to {dest} (the repo is about to be wiped)\n",
          flush=True)
    env = dict(os.environ, QA_ALREADY_RELOCATED="1", QA_RUN_ID=run_id)
    raise SystemExit(subprocess.call(
        [sys.executable, os.path.join(dest, "run_qa.py")] + argv, env=env))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--only", help="comma-separated phases to run")
    ap.add_argument("--skip", help="comma-separated phases to skip")
    ap.add_argument("--run-id", help="reuse a run id (for a resumed run)")
    ap.add_argument("--no-relocate", action="store_true",
                    help="do not copy the harness out of the repo first")
    args = ap.parse_args()

    only = set(filter(None, (args.only or "").split(",")))
    skip = set(filter(None, (args.skip or "").split(",")))

    try:
        cfg = qa_config.load()
    except qa_config.ConfigError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2

    run_id = args.run_id or os.environ.get("QA_RUN_ID")

    # Relocate unless the wipe is being skipped — no wipe, no self-deletion.
    wipe_will_run = "wipe" not in skip and (not only or "wipe" in only)
    relocated = os.environ.get("QA_ALREADY_RELOCATED") == "1"
    if wipe_will_run and not relocated and not args.no_relocate:
        run_dir, run_id = timeline_lib.new_run(cfg)
        _self_copy_and_exec(sys.argv[1:], run_id)

    run_dir, run_id = timeline_lib.new_run(cfg, run_id)

    redactor = qa_redact.Redactor(cfg.secrets())
    tl = timeline_lib.Timeline(run_dir, run_id, redactor=redactor)
    ctx = runner_lib.PhaseContext(cfg, tl, run_dir, {}, redactor)
    runner = runner_lib.Runner(ctx)

    from phases import endpoint, endpoint_linux, features, platform, workflows, wrapup
    platform.register(runner, cfg)
    endpoint.register(runner, cfg)
    # The Linux profile: enrol the appliance itself as an endpoint, then drive
    # the backend's HTTP surface directly. Both self-register only when their
    # config flag is on, so an operator's existing Windows run is unchanged.
    endpoint_linux.register(runner, cfg)
    features.register(runner, cfg)
    workflows.register(runner, cfg)
    # Collection and teardown are registered last so they run after the
    # workflows: collect BEFORE teardown so nothing needed for the report is
    # destroyed, teardown BEFORE the report so its problems appear in it.
    wrapup.register(runner, cfg)
    # Re-register teardown after collect by reordering: endpoint registered it
    # early (it needs `enrol`), so move it to just before the report.
    _reorder(runner, "teardown", before="report")
    _reorder(runner, "teardown_linux", before="report")

    print("=" * 78)
    print(f"Intact.AI QA — {run_id}")
    print(f"  platform : {cfg.platform_host}")
    print(f"  windows  : {cfg.windows_host or 'none — Linux-only run'}")
    print(f"  results  : {run_dir}")
    print(f"  phases   : {', '.join(p['name'] for p in runner.phases)}")
    if skip:
        print(f"  skipping : {', '.join(sorted(skip))}")
    print("=" * 78 + "\n")

    tl.event("run_begin", detail={
        "platform": cfg.platform_host, "windows": cfg.windows_host,
        "commit": _git_head(cfg.repo_dir), "relocated": relocated})

    results = runner.run(only=only or None, skip=skip or None)
    counts = runner_lib.summarize(results)

    tl.event("run_end", status="ok" if not counts.get("fail") and
             not counts.get("error") else "fail", detail=counts)

    print("\n" + "=" * 78)
    for r in results.values():
        mark = {"pass": "✓", "fail": "✗", "error": "!", "skip": "-"}.get(r.status, "?")
        extra = f"  ({r.skipped_because})" if r.skipped_because else ""
        print(f"  {mark} {r.name:<14} {r.status or '?':<7} {r.duration_s or 0:>6}s{extra}")
    print("=" * 78)
    print(f"  passed {counts.get('pass', 0)}   failed {counts.get('fail', 0)}   "
          f"errored {counts.get('error', 0)}   skipped {counts.get('skip', 0)}")
    print(f"\n  Report:   {os.path.join(run_dir, 'REPORT.md')}")
    print(f"  Timeline: {os.path.join(run_dir, 'timeline.md')}\n")

    return 1 if (counts.get("fail") or counts.get("error")) else 0


def _reorder(runner, name, before):
    """Move a registered phase so it runs just before another."""
    phases = runner.phases
    moving = next((p for p in phases if p["name"] == name), None)
    anchor = next((i for i, p in enumerate(phases) if p["name"] == before), None)
    if moving is None or anchor is None:
        return
    phases.remove(moving)
    anchor = next(i for i, p in enumerate(phases) if p["name"] == before)
    phases.insert(anchor, moving)


def _git_head(repo_dir=None):
    """The commit under test.

    Takes the repo from the config rather than a hard-coded /home/tenroot/intact:
    CI installs to /mnt/intact, and a wrong path here silently reported the
    commit of whatever tree happened to be at the old location — or None, which
    is worse, because the report then names no commit at all."""
    try:
        r = subprocess.run(["git", "-C", repo_dir or "/home/tenroot/intact",
                            "rev-parse", "--short", "HEAD"],
                           capture_output=True, text=True, timeout=15)
        return r.stdout.strip() or None
    except Exception:                                         # noqa: BLE001
        return None


if __name__ == "__main__":
    sys.exit(main())
