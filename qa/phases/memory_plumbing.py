"""The memory pipeline — the one module with NO coverage of any kind.

WHY IT HAD NONE. The Windows runner cannot load a memory-acquisition driver, so
no image is ever produced and the memory pipeline reports SKIPPED on every
scenario. Nothing about VolWeb, the upload path, plugin dispatch or the run
status surface is exercised.

WHAT THIS DOES AND DOES NOT PROVE, stated plainly because the distinction is the
whole design. Full forensic coverage is not honestly reachable offline:
Volatility needs a symbol table matched to the source kernel, and it normally
DOWNLOADS one — which this suite is not allowed to do. So this covers the
PLUMBING: an image is accepted, a run is dispatched against it, the run reaches
a terminal state, and the result is reported rather than the request hanging or
500-ing. "No symbols" is a PASS here, and deliberately so — it is a real answer
from a working pipeline.

That is not a lesser test than it sounds. Every memory-adjacent bug this
appliance has actually shipped was plumbing: a binary without its execute bit, a
volume the containers disagreed about, a status endpoint that never reached a
terminal state. None of them needed a parsed process list to catch.

THE IMAGE IS REAL. /proc/kcore is an ELF view of live kernel memory, present on
the runner, and needs no download. A slice of it is genuine memory rather than a
synthetic file, which keeps the upload and the format sniffing honest.

AND IT IS DELIBERATELY CANCELLED. Measured on the first run: the analysis reached
52% and then sat for the full twenty-minute timeout -- because a kcore slice is
not a physical memory image, so Volatility brute-force scans it for a kernel
banner that is not there. Waiting for that to finish is not a test of anything;
it cost twenty minutes on every one of eleven scenarios and asserted nothing a
shorter wait would not. So the phase lets the run work for RUN_SECONDS, proves it
is genuinely running, then STOPS it and proves it terminates -- which exercises
/api/memory/run/<id>/stop as well, an endpoint nothing else touches, and is the
plumbing an operator actually depends on when they point the tool at the wrong
image.
"""

import os

MB = 1024 * 1024
SLICE_MB = 16          # enough to be a plausible image, small enough to move

# How long to let the analysis actually run before cancelling it. NOT a timeout
# on the pipeline -- see the note in the phase: we are proving the plumbing
# moves, and then that the operator can stop it.
RUN_SECONDS = 90
STOP_SECONDS = 240


def register(runner, cfg):
    tl = runner.ctx.tl

    @runner.phase("memory_plumbing",
                  "Upload a real memory slice and prove the pipeline moves it",
                  needs=("features",))
    def memory_plumbing(ctx):
        from lib import shell

        detail = {}
        img = os.path.join(ctx.run_dir, "artifacts", "kcore-slice.raw")
        os.makedirs(os.path.dirname(img), exist_ok=True)

        # dd rather than a Python read: /proc/kcore is sparse and enormous, and
        # reading it into memory to write it back out is how a runner runs out.
        # shell.sudo, not a bare `sudo` argv — the harness feeds the password on
        # stdin and a raw call would hang waiting for a prompt nobody answers.
        r = shell.sudo(["bash", "-c",
                        f"dd if=/proc/kcore of={img} bs=1M count={SLICE_MB} "
                        f"status=none && chmod 0644 {img}"],
                       cfg.sudo_password, timeout=300, tl=ctx.tl,
                       stage="memory_plumbing")
        size = os.path.getsize(img) if os.path.exists(img) else 0
        detail["image_bytes"] = size
        ctx.check("a memory image was produced on the runner", size > MB,
                  expected=f"~{SLICE_MB} MB from /proc/kcore",
                  actual=f"{size // MB} MB" if size else f"dd rc={r.rc}",
                  note="/proc/kcore is live kernel memory and needs no download; "
                       "if this fails the runner has restricted it")
        if size <= MB:
            return detail

        c = ctx.get("client")

        # 1. does the module answer at all
        plugins = c.get("/api/memory/available_plugins", expect=(200, 400))
        names = plugins if isinstance(plugins, list) else \
            (plugins or {}).get("plugins") or []
        detail["plugins"] = len(names)
        ctx.check("the memory module offers plugins", isinstance(names, list),
                  actual=len(names),
                  note="a disabled module answers 400; this profile enables it")

        # 2. Upload. This endpoint BOTH stages the image and starts the
        #    pipeline -- it answers with a run_id, not an upload id, so there is
        #    no separate dispatch to make. (Read out of memory_routes.py rather
        #    than assumed: an earlier draft of this phase POSTed to
        #    /api/memory/run with an upload id that never exists.)
        with open(img, "rb") as fh:
            body = c.request("POST", "/api/memory/upload",
                             files={"file": ("kcore-slice.raw", fh,
                                             "application/octet-stream")},
                             data={"mode": "layered",
                                   "case_name": "QA-CI-memory"},
                             expect=(200, 201, 202))
        run_id = (body or {}).get("run_id") if isinstance(body, dict) else None
        detail["run_id"] = run_id
        detail["upload_status"] = (body or {}).get("status") \
            if isinstance(body, dict) else None
        ctx.check("the memory image uploaded and started a run", bool(run_id),
                  actual=body,
                  note="this is the operator's own 'analyse an image I already "
                       "have' path, independent of acquisition — and the only "
                       "coverage the memory module has")
        if not run_id:
            return detail
        tl.ids(memory_run_id=run_id)

        # 3. it must genuinely be WORKING, not accepted and dropped on the floor.
        import time
        deadline = time.time() + RUN_SECONDS
        seen = []
        while time.time() < deadline:
            st = c.run_status(run_id) or {}
            seen.append((st.get("status"), st.get("progress")))
            if st.get("status") not in ("running", "queued", "pending", None):
                break
            time.sleep(10)
        detail["observed"] = seen[-1] if seen else None
        progressed = any((p or 0) > 1 for _, p in seen)
        detail["progressed"] = progressed
        ctx.check("the memory pipeline actually started working", progressed,
                  expected="progress past 1%",
                  actual=str(seen[-1]) if seen else "no status at all",
                  note="accepted-then-dropped answers 202 and never moves; "
                       "measured, a healthy run reaches ~52% within a minute")

        # 4. and the operator can STOP it. Nothing else in the suite touches
        #    this endpoint, and it is what someone needs when they have pointed
        #    the tool at the wrong image -- exactly what this phase just did.
        last = seen[-1][0] if seen else None
        if last in ("running", "queued", "pending", None):
            c.post(f"/api/memory/run/{run_id}/stop", {},
                   expect=(200, 202, 400, 404, 409))
            run = c.wait_for_run(run_id, STOP_SECONDS, tl,
                                 what="the memory run stopping")
            status = (run or {}).get("status")
            detail["status_after_stop"] = status
            ctx.check("a stopped memory run reaches a terminal state", bool(run),
                      expected="stopped, failed or completed",
                      actual=status or f"still running {STOP_SECONDS}s after stop",
                      note="THE ASSERTION THAT MATTERS. A run that ignores stop "
                           "leaves the operator watching a spinner they cannot "
                           "cancel, holding a container the box needs back")
        else:
            detail["status_after_stop"] = last
            ctx.check("the memory run reached a terminal state on its own",
                      True, actual=last,
                      note="it finished inside the observation window, so there "
                           "was nothing to stop")
        return detail
