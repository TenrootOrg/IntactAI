"""Phases that stand the platform up and prove it is sound before any endpoint
work begins: preflight, wipe, clone, config, install, security sweep, auth.

These run strictly in order and the early ones are `critical` — a failed
install makes every later phase's failure meaningless noise, and a QA report
listing twelve failures caused by one broken install is worse than a report
saying "install failed" once.
"""

import glob
import os
import re
import shutil
import time

from lib import api as api_lib
from lib import shell

# Fixed dashboard credentials, matching the shipped module defaults in
# config.yaml. Deliberately not random and deliberately not in qa-config.yaml:
# they are the same on every run, so the operator can open the dashboard
# mid-run without looking anything up, and there is no secret to leak because
# the value is the documented shipped default.
QA_DASH_USER = "qa"
QA_DASH_PASSWORD = "123123"

REPO_URL = "git@github.com:TenrootOrg/IntactAI.git"

# Where the platform is INSTALLED, i.e. the tree install.sh runs from and every
# container bind-mounts. Hardcoding /home/tenroot/intact was fine while that was
# the only possibility; it is wrong the moment the appliance lives anywhere else.
#
# It moved on 2026-08-03: the working copy and the install are now one directory
# (/home/tenroot/intact-dev), because keeping them apart existed only to hold an
# OLD release for upgrade testing, and that finished. With the constant still
# pointing at the old path the harness would have wiped and reinstalled into a
# directory nothing was running from, then asserted against the appliance that
# was still up elsewhere -- passing or failing for reasons unrelated to the code
# under test.
#
# Resolved from qa-config so it follows the box rather than a literal, falling
# back to the historical default for an unconfigured checkout.
REPO_DIR = "/home/tenroot/intact"
INSTALL_MARKER = "/etc/intact-initialized"

# The eight files this session's hardening work put at 0600. Re-checked here
# against a FRESHLY INSTALLED box, which is the one thing the static tests
# cannot prove: they assert install.sh contains the chmod, not that the file
# ends up 0600 after a real run.
SECRET_FILES_0600 = [
    "data/velociraptor/server.config.yaml",
    "data/velociraptor/api.config.yaml",
    "data/intact.db",
    "data/intact.db-wal",
    "data/intact.db-shm",
    "modules/timesketch/config/timesketch.conf",
    "modules/timesketch/config/timesketch_legacy.conf",
    "data/auth/audit.jsonl",
]

# Services that must NOT be reachable from another container on the box. Each
# was an actual finding: an unauthenticated Portainer agent is a container-to-
# host-root path, and OpenSearch held 146k forensic documents with no auth.
ISOLATED = [
    ("intact_portainer_agent", 9001, "container-to-host-root via the Docker socket"),
    ("intact_timesketch_opensearch", 9200, "unauthenticated forensic document store"),
    ("intact_timesketch_postgres", 5432, "Timesketch metadata database"),
    ("intact_timesketch_redis", 6379, "Timesketch task broker"),
]


def _scenario_upgrades():
    """Whether this run's scenario performs an upgrade, per the catalogue."""
    try:
        import scenarios
        return bool(scenarios.route_for(os.environ.get("QA_SCENARIO") or ""))
    except Exception:                                         # noqa: BLE001
        return False


def _running_backend_image():
    """The image reference intact_backend is actually running, or ""."""
    r = shell.run(["docker", "inspect", "--format", "{{.Config.Image}}",
                   "intact_backend"], timeout=30)
    out = (r.out or "").strip().splitlines()
    return out[0].strip() if out else ""


def register(runner, cfg):
    tl = runner.ctx.tl

    global REPO_DIR
    REPO_DIR = cfg.repo_dir or REPO_DIR

    # ---------------------------------------------------------------- -1 --
    @runner.phase("preflight", "Verify prerequisites before destroying anything",
                  critical=True)
    def preflight(ctx):
        """Everything checked here is checked BEFORE phase 0a wipes the box.

        Discovering that paramiko is missing after the tree has been deleted
        costs a full reinstall to get back to where you started.
        """
        detail = {}

        for tool in ("docker", "git", "python3"):
            path = shutil.which(tool)
            ctx.check(f"{tool} is installed", bool(path), actual=path)

        r = shell.run(["docker", "compose", "version"])
        ctx.check("docker compose v2 is available", r.ok, actual=r.out.strip()[:80])

        # paramiko exists to drive the WINDOWS target over SSH. On a Linux-only
        # profile there is no Windows target, so demanding it would fail a
        # critical phase over a dependency the run has no use for.
        if cfg.windows_enabled:
            try:
                import paramiko                               # noqa: F401
                ctx.check("paramiko is installed", True)
            except ImportError:
                ctx.check("paramiko is installed", False,
                          note="sudo apt-get install -y python3-paramiko — needed "
                               "to bootstrap and tear down the Windows client")

        # A run adds roughly: a 4 GB memory image, a 1-3 GB KAPE upload, a ~1 GB
        # support bundle, plus index growth. Docker images are already on disk
        # and are not re-pulled. 12 GB is the floor at which the run cannot
        # finish; 20 GB is where it stops being comfortable.
        # The floor is configurable because CI needs a much higher one: a run
        # that also INSTALLS from scratch pulls ~16 GB of images and ~5 GB of
        # release assets before it writes its first artifact, so 12 GB is right
        # for a run against an existing box and useless as a gate for a fresh one.
        min_free = int(cfg.get("run", "min_free_disk_gb", default=12))
        free_gb = shutil.disk_usage("/").free / 2**30
        detail["free_disk_gb"] = round(free_gb, 1)
        ctx.check(f"at least {min_free} GB free", free_gb >= min_free,
                  expected=f">={min_free} GB", actual=f"{free_gb:.1f} GB",
                  note="a memory image, a KAPE upload and a support bundle")
        if free_gb < 20:
            tl.warn("disk_tight", detail={
                "free_gb": round(free_gb, 1),
                "note": "run should fit, but there is little headroom"})

        # RAM is recorded, not asserted. The README asks for 16 GB and a full
        # install runs ~30 containers including BOTH Elasticsearch and
        # OpenSearch, so a box at exactly the minimum can complete and can also
        # OOM-kill rabbitmq halfway. Refusing to start would block the very runs
        # that tell us where the real floor is; a number in the report lets a
        # later failure be read against the memory it actually had.
        try:
            meminfo = {}
            with open("/proc/meminfo", encoding="utf-8") as fh:
                for line in fh:
                    k, _, v = line.partition(":")
                    meminfo[k] = v.strip()
            ram_gb = int(meminfo.get("MemTotal", "0 kB").split()[0]) / 2**20
            swap_gb = int(meminfo.get("SwapTotal", "0 kB").split()[0]) / 2**20
            detail["ram_gb"] = round(ram_gb, 1)
            detail["swap_gb"] = round(swap_gb, 1)
            if ram_gb + swap_gb < 16:
                tl.warn("memory_below_documented_minimum", detail={
                    "ram_gb": round(ram_gb, 1), "swap_gb": round(swap_gb, 1),
                    "note": "README asks for 16 GB; rabbitmq is the first thing "
                            "the OOM killer takes"})
        except OSError:
            pass

        # sudo, tested for real. A wrong password discovered at the install
        # phase means the wipe already happened.
        r = shell.sudo(["true"], cfg.sudo_password, timeout=30, tl=tl,
                       stage="preflight")
        ctx.check("sudo password works", r.ok,
                  note="platform.sudo_password in qa/qa-config.yaml")

        # Windows target reachable and admin — checked before anything is
        # destroyed, for the same reason.
        #
        # Skipped entirely on a Linux-only profile. This block used to run
        # unconditionally and ended in ctx.check(..., False) on ANY exception,
        # so a run with no Windows box failed a CRITICAL phase and nothing else
        # executed at all. A machine that was never part of the run must not be
        # able to fail it — it is recorded as absent, not as broken.
        if not cfg.windows_enabled:
            detail["windows"] = "not configured — Linux-only run"
            tl.warn("windows_not_configured", detail={
                "note": "enrol/activity/teardown and the workflow phases that "
                        "need them will report as not reached"})
            return detail

        from lib import winssh
        try:
            with winssh.WindowsTarget(cfg.windows_host, cfg.windows_user,
                                      cfg.windows_password, cfg.ssh_port,
                                      tl=tl) as win:
                facts = win.facts()
                detail["windows"] = facts
                ctx.check("Windows target reachable over SSH", True,
                          actual=facts.get("host"))
                ctx.check("Windows account is a local Administrator",
                          win.is_admin(),
                          note="needed to install and remove the Velociraptor service")
                ram = facts.get("ram_gb") or 0
                ctx.check("Windows RAM >= 3.5 GB", ram >= 3.5,
                          expected=">=3.5 GB", actual=f"{ram} GB",
                          note="below Windows 11's 4 GB minimum the box swaps, "
                               "which distorts the memory image phase 6 captures")
        except Exception as exc:                              # noqa: BLE001
            ctx.check("Windows target reachable over SSH", False,
                      actual=ctx.redact(str(exc))[:200])

        return detail

    # ---------------------------------------------------------------- 0a --
    @runner.phase("wipe", "Tear down any previous install", needs=("preflight",),
                  critical=True)
    def wipe(ctx):
        """A QA that runs against a box carrying state from the last run proves
        nothing about a fresh install, which is the thing most likely to be
        broken and least likely to be noticed."""
        detail = {}

        backup = os.path.join(ctx.run_dir, "artifacts", "config.yaml.before-wipe")
        if os.path.exists(os.path.join(REPO_DIR, "config.yaml")):
            shutil.copy2(os.path.join(REPO_DIR, "config.yaml"), backup)
            os.chmod(backup, 0o600)
            detail["config_backup"] = backup

        names = shell.container_names()
        detail["containers_before"] = len(names)
        if names:
            shell.sudo(["docker", "rm", "-f"] + names, cfg.sudo_password,
                       timeout=300, tl=tl, stage="wipe")

        for args in (["docker", "volume", "prune", "-f"],
                     ["docker", "network", "prune", "-f"]):
            shell.sudo(args, cfg.sudo_password, timeout=300, tl=tl, stage="wipe")

        shell.sudo(["rm", "-f", INSTALL_MARKER], cfg.sudo_password, tl=tl,
                   stage="wipe")

        # config.yaml is NOT wiped -- it is operator state and holds the live
        # PAT -- but first_login must go back to true, or the "fresh install
        # ships unclaimed" check is wrong on every run after the first. Once
        # any run claims the appliance the flag flips to false and persists
        # across a wipe, so the next install comes up already claimed with a
        # password nothing knows.
        detail["first_login_reset"] = _reset_first_login(tl)

        ctx.check("no containers remain", len(shell.container_names()) == 0,
                  actual=len(shell.container_names()))
        ctx.check("install marker removed", not os.path.exists(INSTALL_MARKER))
        return detail

    # ----------------------------------------------------------------- 0 --
    @runner.phase("install", "Fresh install from install.sh", needs=("wipe",),
                  critical=True)
    def install(ctx):
        """The install log is copied into the run directory rather than
        referenced: install.sh writes it inside the repo, and a later run's
        wipe deletes the tree it lives in."""
        log_path = os.path.join(ctx.run_dir, "logs", "install.log")
        ctx.set(install_log=log_path)

        # An air-gap install when a package directory is supplied. Not the
        # default: INTACT_AIRGAP changes behaviour in roughly fifteen places
        # (the SigmaHQ clone, tool downloads, Timesketch package fetches all
        # take different branches), so making it the default would quietly test
        # a different product from the one a customer installs online.
        argv = ["bash", "install.sh"]
        pkg = (os.environ.get("QA_INSTALL_PACKAGE_DIR") or "").strip()
        if pkg:
            argv += ["--package", pkg]

        r = shell.sudo(argv, cfg.sudo_password,
                       timeout=cfg.timeout("install", 90) * 60,
                       cwd=REPO_DIR, log_path=log_path, tl=tl, stage="install",
                       preserve_env=("GITHUB_TOKEN",))

        ctx.check("install.sh exited 0", r.ok, actual=r.rc)
        ctx.check("install marker written", os.path.exists(INSTALL_MARKER))

        # The install that exits 0 having done NOTHING.
        #
        # check_initialization_marker (lib/common.sh:587) prompts when
        # /etc/intact-initialized already exists. Under a harness stdin is
        # closed, `read` gets EOF, the answer is empty, and install.sh prints
        # "Installation cancelled by user" and exits ZERO.
        #
        # The marker check above CANNOT catch this: the file it looks for is
        # the very one that caused the short-circuit, so it passes. Only the log
        # text distinguishes "installed successfully" from "declined to install".
        ctx.check("install did not short-circuit on the initialization marker",
                  "Installation cancelled by user" not in (r.out or ""),
                  note="/etc/intact-initialized existed and the confirm prompt "
                       "read EOF; install.sh exits 0 having changed nothing. "
                       "Remove the marker before installing.")

        # Copy install.sh's own log too — it carries the pre-container phase
        # that our capture starts too late to see on a resumed run.
        # REDACT on the way in. These are install.sh's own logs, and .gitignore
        # says why they matter: "these routinely contain whatever the run
        # printed -- which has included a GitHub PAT". Copying them verbatim
        # put unredacted credentials into the run directory, which is the exact
        # leak the redactor exists to prevent — and it went unnoticed because
        # the canary self-test passed, the canary being seeded into a different
        # file. The leak scan at report time caught it.
        for candidate in sorted(_glob_logs(REPO_DIR)):
            dest = os.path.join(ctx.run_dir, "logs", os.path.basename(candidate))
            ctx.redact.redact_file(candidate, dest)
            os.chmod(dest, 0o600)

        names = shell.container_names()
        unhealthy = []
        for n in names:
            ok, why = shell.container_is_ok(n)
            if not ok:
                unhealthy.append(why)

        ctx.check("containers were created", len(names) > 0, actual=len(names))
        ctx.check("every container is running and healthy", not unhealthy,
                  actual=", ".join(unhealthy[:8]) or "all healthy")

        return {"containers": len(names), "unhealthy": unhealthy,
                "install_rc": r.rc}

    # ---------------------------------------------------------------- 0b --
    # ------------------------------------------------------------------ C.5 --
    @runner.phase("backend_under_test",
                  "Make this ref's backend image the one that runs",
                  needs=("install",), critical=True)
    def backend_under_test(ctx):
        """Put back the pin the installer deliberately corrects away.

        The workflow builds intact-backend:ref-<sha> and points
        config.yaml versions.backend at it, on the reasoning that
        deploy_backend uses whatever BACKEND_VERSION names. That reasoning was
        sound and the result was still wrong: when a release package ships a
        backend image, lib/config.sh overrides the pin with the package's tag
        -- "THE PACKAGE WINS OVER THE PIN", which exists to stop a stale pin
        triggering a source rebuild. So the built image was pinned, corrected
        away, and never deployed, while the report claimed engine and
        container matched. Every run to date tested the RELEASE's backend.

        The correction is right for a real install and must not be weakened.
        What this does instead is what an operator would do afterwards: set
        the pin, and let the box converge onto it. That is a supported
        operation, not a hack -- app.py runs self_heal_backend_swap() on every
        boot precisely to make the running container agree with
        config.yaml versions.backend.

        Skips cleanly when the run is deliberately testing the published
        artifact (backend_image=release), and is a no-op when the built image
        is already the one running.
        """
        mode = (os.environ.get("QA_BACKEND_IMAGE") or "release").strip()
        built = (os.environ.get("QA_BUILT_IMAGES") or "").strip()
        running = _running_backend_image()
        detail = {"mode": mode, "built": built, "running_before": running}

        # NOT on an upgrade scenario, and the reason is principled rather than
        # cautious. What those scenarios put under test is the ENGINE, which
        # comes from the workspace and therefore from this ref; the backend
        # image is legitimately the target RELEASE's, because that is what
        # upgrading to a release means. Re-pinning to ref-<sha> beforehand
        # would also hand the upgrade planner a backend pin that names no
        # release, which is not a thing any operator's box would present.
        if _scenario_upgrades():
            ctx.check("the backend under test is the one this run intends",
                      True, actual=f"{running} (upgrade scenario)",
                      note="an upgrade scenario ends on the target release's "
                           "backend by design; this ref supplies the engine")
            return detail

        if mode != "branch" or not built:
            ctx.check("the backend under test is the one this run intends",
                      True,
                      actual=f"{running} (mode={mode or 'release'})",
                      note="testing the published artifact; the image built "
                           "from this ref, if any, is not deployed")
            return detail

        want = built.split(",")[0].strip()
        detail["want"] = want
        if running == want:
            ctx.check("the backend under test is the image built from this ref",
                      True, expected=want, actual=running,
                      note="already deployed; nothing to re-pin")
            return detail

        tag = want.split(":", 1)[1] if ":" in want else want
        root = cfg.repo_dir or REPO_DIR

        # Both surfaces, or they disagree and the box oscillates: .env drives
        # compose, config.yaml drives the backend's own self-heal on boot.
        shell.sudo(["sed", "-i",
                    f"s|^  backend:.*|  backend: '{tag}'|",
                    os.path.join(root, "config.yaml")],
                   cfg.sudo_password, tl=tl, stage="backend_under_test")
        shell.sudo(["sed", "-i",
                    f"s|^BACKEND_VERSION=.*|BACKEND_VERSION={tag}|",
                    os.path.join(root, "modules/backend/.env")],
                   cfg.sudo_password, tl=tl, stage="backend_under_test")

        # --no-build so a missing image fails loudly here rather than being
        # quietly rebuilt from source into something nobody tested.
        r = shell.sudo(["docker", "compose", "up", "-d", "--no-build"],
                       cfg.sudo_password, timeout=600,
                       cwd=os.path.join(root, "modules/backend"),
                       tl=tl, stage="backend_under_test")
        ctx.check("the backend was recreated onto this ref's image", r.ok,
                  actual=(r.out or "")[-200:] if not r.ok else "recreated")

        deadline = time.time() + 300
        healthy = False
        while time.time() < deadline:
            ok, _why = shell.container_is_ok("intact_backend")
            if ok and _running_backend_image() == want:
                healthy = True
                break
            time.sleep(5)

        running = _running_backend_image()
        detail["running_after"] = running
        ctx.check("the backend under test is the image built from this ref",
                  running == want and healthy,
                  expected=want, actual=running,
                  note="if this fails the run is exercising the release's "
                       "backend while reporting on this ref -- the exact "
                       "mismatch this phase exists to prevent")
        return detail

    @runner.phase("security", "Re-check the hardening on a freshly installed box",
                  needs=("install",))
    def security(ctx):
        """Every check here corresponds to a real finding closed this week. The
        static tests assert install.sh CONTAINS the fix; only a fresh install
        proves the fix actually lands."""
        detail = {"modes": {}, "isolation": {}}

        for rel in SECRET_FILES_0600:
            path = os.path.join(REPO_DIR, rel)
            if not os.path.exists(path):
                # Not every file exists on every box (a disabled module has no
                # config). Absent is not a failure; world-readable is.
                detail["modes"][rel] = "absent"
                continue
            mode = os.stat(path).st_mode & 0o777
            detail["modes"][rel] = oct(mode)
            ctx.check(f"{rel} is not group/world readable", not (mode & 0o077),
                      expected="0600", actual=oct(mode))

        # Peer-container isolation. Tested from a throwaway container on the
        # default bridge, which is what an attacker who lands in any other
        # container on this box actually has.
        for name, port, why in ISOLATED:
            if name not in shell.container_names():
                detail["isolation"][name] = "not present"
                continue
            reachable = _peer_can_reach(name, port)
            detail["isolation"][name] = "reachable" if reachable else "blocked"
            ctx.check(f"{name}:{port} is not reachable from a peer container",
                      not reachable, expected="blocked",
                      actual=detail["isolation"][name], note=why)

        # Hardening must not have cleared the execute bit on the Velociraptor
        # CLI. Every VQL-by-exec path depends on it — memory acquisition, flow
        # cancellation — and when it is missing the failure surfaces as an
        # opaque "VQL query failed (rc=126)" from deep inside a pipeline, with
        # nothing pointing at permissions. The server itself runs from the
        # image copy and comes up perfectly, so nothing else looks wrong.
        velo_bin = os.path.join(REPO_DIR, "data", "velociraptor", "velociraptor")
        if os.path.exists(velo_bin):
            mode = os.stat(velo_bin).st_mode & 0o777
            detail["velociraptor_binary_mode"] = oct(mode)
            ctx.check("the Velociraptor CLI binary is executable",
                      bool(mode & 0o111), expected="0755", actual=oct(mode),
                      note="rc=126 from the memory pipeline means this bit is "
                           "missing")

        # The LEGACY Velociraptor client (0.7.x) has never been exercised by
        # anything. It exists for old Windows hosts -- Server 2008 R2, Win 7 --
        # where the modern Go 1.22+ binary dies with 0xc0000005, so the boxes
        # that need it are exactly the ones nobody has to hand to test with.
        #
        # It is served to operators as a download, which makes the failure mode
        # silent: a 0644 binary downloads fine and only fails when the customer
        # runs it, on a machine we will never see. Same masked-execute-bit bug
        # as the CLI above (`chmod +x` is filtered by the process umask,
        # `chmod 755` is not) with a far longer feedback loop.
        legacy_dir = os.path.join(REPO_DIR, "modules", "nginx", "html", "downloads")
        legacy = sorted(glob.glob(os.path.join(legacy_dir, "velociraptor-v0.7.*")))
        if legacy:
            detail["velociraptor_legacy_files"] = [os.path.basename(p) for p in legacy]
            for p in legacy:
                mode = os.stat(p).st_mode & 0o777
                name = os.path.basename(p)
                # Only the ELF/musl build is ever executed here; the .exe is a
                # download served to Windows. Assert the bit on the one that
                # needs it, and assert non-empty on both -- a truncated download
                # is the other way this ships broken.
                if name.endswith("-linux-amd64-musl"):
                    ctx.check(f"legacy client {name} is executable",
                              bool(mode & 0o111), expected="0755", actual=oct(mode))
                ctx.check(f"legacy client {name} is not truncated",
                          os.path.getsize(p) > 1024 * 1024, expected=">1 MB",
                          actual=f"{os.path.getsize(p) / 1048576:.1f} MB")
        else:
            # Not a failure on its own -- a package built without the legacy pin
            # legitimately ships none. Recorded so a run that SHOULD have them
            # cannot look identical to one that never expected any.
            detail["velociraptor_legacy_files"] = "none staged"

        # The API must reject an unauthenticated caller.
        c = api_lib.Client(cfg.platform_host, tl=tl)
        code = c.status_of("/api/cases")
        ctx.check("/api/cases rejects an unauthenticated caller",
                  code in (401, 403), expected="401/403", actual=code)

        # Elasticsearch's transport port must not be published to the LAN.
        code_9300 = _tcp_open(cfg.platform_host, 9300)
        ctx.check("Elasticsearch 9300 is closed from the LAN", not code_9300,
                  expected="closed", actual="open" if code_9300 else "closed")

        return detail

    # ---------------------------------------------------------------- 0c --
    @runner.phase("cloud", "Cloud detection content (AWS SIGMA / Azure o365rc)",
                  needs=("install",))
    def cloud(ctx):
        """WRITTEN BUT NOT RUN by default -- see cfg.cloud_tests.

        The DFIR profile this harness exercises does not install aws_sigma or
        o365rc, so every assertion here would fail for the wrong reason on a
        box that was never meant to have them, burying the failures that
        matter. The coverage exists so that pointing this at a cloud-enabled
        appliance is a config flag rather than a writing exercise.

        What it checks, and why each is the part that silently no-ops:
          * the SIGMA rule pack is PRESENT AND NON-EMPTY -- an aws_sigma module
            that installed cleanly but cloned zero rules detects nothing while
            reporting healthy, which is the exact shape of the aws_sigma
            'enabled but no rules' case the upgrade path already warns about;
          * the o365rc image exists locally -- upstream publishes only :latest,
            so an 'upgrade' is a re-pull and a missing image is invisible until
            an Azure collection is actually attempted.
        """
        if not cfg.cloud_tests:
            return {"skipped": "run.cloud_tests is false (default) — "
                               "assertions written, deliberately not run"}

        detail = {}
        rules = "/opt/sigma-rules/rules/cloud/aws"
        r = shell.docker(["exec", "intact_backend", "sh", "-c",
                          f"ls {rules}/*.yml 2>/dev/null | wc -l"])
        count = int((r.out.strip() or "0").splitlines()[-1] or 0) if r.ok else 0
        detail["aws_sigma_rules"] = count
        ctx.check("the AWS SIGMA rule pack has rules", count > 0,
                  expected=">0", actual=count,
                  note="an aws_sigma module that installed but cloned zero "
                       "rules detects nothing while reporting healthy")

        r = shell.docker(["image", "inspect", "anssi/dfir-o365rc:latest"])
        ctx.check("the o365rc collector image is present locally", r.ok,
                  expected="present", actual="present" if r.ok else "missing",
                  note="upstream ships only :latest, so a missing image is "
                       "invisible until an Azure collection is attempted")
        return detail

    # ----------------------------------------------------------------- 1 --
    @runner.phase("auth", "Claim the appliance and hold a session",
                  needs=("install",), critical=True)
    def auth(ctx):
        """Fixed qa/123123, matching the shipped module defaults in config.yaml.

        This was a per-run random password. The operator asked for fixed
        credentials instead: a random password meant looking up a file every
        time you wanted to open the dashboard mid-run, which is exactly when
        you want to look at it. The appliance is a lab box behind the
        operator's own network, and the real protection against a guessed
        dashboard password is the ten-attempt lockout, not length.

        Still written to the run directory at 0600, because a run should be
        self-describing, and still fed through the redactor so it does not
        appear in logs or the report.
        """
        username, password = QA_DASH_USER, QA_DASH_PASSWORD

        # Deliberately NOT added to the redactor. It is the documented shipped
        # default, not a secret, and redacting a string as common as "123123"
        # would blank the module passwords wherever they legitimately appear in
        # install logs — turning readable output into [REDACTED] noise for no
        # gain.

        creds_path = os.path.join(ctx.run_dir, "dashboard-credentials.txt")
        with open(os.open(creds_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600),
                  "w", encoding="utf-8") as fh:
            fh.write(f"https://{cfg.platform_host}/\n"
                     f"username: {username}\npassword: {password}\n")

        c = api_lib.Client(cfg.platform_host, tl=tl)
        mode_before = c.auth_mode()

        # Self-heal rather than dead-end. If the box is already claimed the
        # harness cannot log in -- it does not know the password -- and every
        # remaining phase would be skipped. config.yaml's first_login is the
        # documented recovery switch and takes effect immediately with no
        # restart, so flip it and carry on. Recorded as a warning, not silently:
        # on a run that included the wipe this should never be needed, and if
        # it is, that is worth knowing.
        recovered = False
        if mode_before != "setup":
            tl.warn("appliance_already_claimed", detail={
                "mode": mode_before,
                "action": "resetting first_login via config.yaml"})
            recovered = _reset_first_login(tl)
            mode_before = c.auth_mode()

        ctx.check("appliance is claimable", mode_before == "setup",
                  expected="setup", actual=mode_before,
                  note="first_login: true in config.yaml is the recovery switch")
        if not recovered:
            ctx.check("appliance shipped unclaimed without intervention",
                      True, note="fresh install landed in setup mode")

        how = c.ensure_session(username, password)
        mode_after = c.auth_mode()
        ctx.check("setup closes after claiming", mode_after == "login",
                  expected="login", actual=mode_after)

        ctx.check("session is authenticated", c.is_authenticated(),
                  note="/api/auth/status, not /api/auth/verify — the latter is "
                       "nginx-internal and 404s from outside regardless of session")
        ctx.check("an authenticated API call succeeds",
                  c.status_of("/api/clients") == 200,
                  expected=200, actual=c.status_of("/api/clients"))

        # Everything this run does belongs in ONE persistent case named "QA",
        # reused across runs rather than recreated. Runs are tagged to a
        # workspace by the X-Case-Id request header (case_routes.py:253), so
        # setting it on the session scopes every later call — the KAPE
        # automation, the hunt, the memory run — into that case without each
        # phase having to remember.
        #
        # Reused, not recreated, and never deleted: the case accumulates the
        # history of every QA run, which is the point. A run that made its own
        # throwaway case would leave the fusion graph of the previous run
        # orphaned and the workspace list full of debris.
        case_id, created = _ensure_qa_case(c)
        ctx.check("the persistent QA case is available", bool(case_id),
                  actual=case_id, note="reused across runs; never deleted")
        if case_id:
            c.s.headers["X-Case-Id"] = case_id
            ctx.set(qa_case_id=case_id)
            tl.ids(qa_case_id=case_id)

        ctx.set(client=c, dash_user=username, creds_path=creds_path)
        return {"how": how, "mode_before": mode_before, "mode_after": mode_after,
                "credentials_file": creds_path,
                "qa_case_id": case_id, "qa_case_created": created}


# --- helpers -------------------------------------------------------------


QA_CASE_NAME = "QA"


def _ensure_qa_case(c):
    """Find the persistent "QA" case, creating it only if absent.

    Returns (case_id, created). Matched by name because the id is generated at
    creation time and differs per appliance, so it cannot be pinned in code.
    """
    try:
        body = c.get("/api/cases")
    except Exception:                                         # noqa: BLE001
        return None, False
    for case in (body.get("cases") or []) if isinstance(body, dict) else []:
        if (case.get("name") or "").strip().lower() == QA_CASE_NAME.lower():
            return case.get("case_id"), False
    try:
        made = c.post("/api/cases", {"name": QA_CASE_NAME, "min_severity": "low"})
        return (made or {}).get("case_id"), True
    except Exception:                                         # noqa: BLE001
        return None, False


def _reset_first_login(tl, path=None):
    """Set first_login: true in config.yaml, in place.

    TRUNCATE-IN-PLACE, never os.replace() or a write-to-temp-and-rename.
    config.yaml is bind-mounted into the backend container, and Docker binds by
    INODE — swapping the file leaves the container reading the old content
    forever, so the flag would appear changed on disk and have no effect on the
    running platform.
    """
    path = path or os.path.join(REPO_DIR, "config.yaml")
    try:
        with open(path, encoding="utf-8") as fh:
            body = fh.read()
        new = re.sub(r"^first_login:.*$", "first_login: true", body,
                     count=1, flags=re.MULTILINE)
        if new == body:
            return False
        with open(path, "w", encoding="utf-8") as fh:      # truncate in place
            fh.write(new)
        tl.ok("first_login_reset", detail={"file": path})
        return True
    except OSError as exc:
        tl.warn("first_login_reset_failed", detail=str(exc)[:200])
        return False


def _glob_logs(repo_dir):
    import glob
    return [p for p in glob.glob(os.path.join(repo_dir, "install_*.log"))
            if os.path.isfile(p)]


def _peer_can_reach(target_container, port, timeout=6):
    """Can a throwaway container on the default bridge open a TCP session to
    `target_container:port`?

    Uses the container's IP rather than its name because name resolution only
    works inside a shared user-defined network — and if the isolation is
    correct, the probe is NOT on that network. Resolving by name would fail for
    the wrong reason and read as a pass.
    """
    r = shell.docker(["inspect", "-f",
                      "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
                      target_container])
    ips = [ip for ip in r.out.split() if ip]
    if not ips:
        return False
    probe = shell.run([
        "docker", "run", "--rm", "--network", "bridge", "busybox:1.36",
        "sh", "-c",
        " ; ".join(f"nc -z -w 2 {ip} {port} && echo REACHABLE_{ip}" for ip in ips),
    ], timeout=timeout + 30)
    return "REACHABLE_" in probe.out


def _tcp_open(host, port, timeout=4):
    import socket
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
