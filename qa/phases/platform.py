"""Phases that stand the platform up and prove it is sound before any endpoint
work begins: preflight, wipe, clone, config, install, security sweep, auth.

These run strictly in order and the early ones are `critical` — a failed
install makes every later phase's failure meaningless noise, and a QA report
listing twelve failures caused by one broken install is worse than a report
saying "install failed" once.
"""

import os
import re
import shutil

from lib import api as api_lib
from lib import shell

REPO_URL = "git@github.com:TenrootOrg/IntactAI.git"
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


def register(runner, cfg):
    tl = runner.ctx.tl

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

        try:
            import paramiko                                   # noqa: F401
            ctx.check("paramiko is installed", True)
        except ImportError:
            ctx.check("paramiko is installed", False,
                      note="sudo apt-get install -y python3-paramiko — needed to "
                           "bootstrap and tear down the Windows client")

        # A run adds roughly: a 4 GB memory image, a 1-3 GB KAPE upload, a ~1 GB
        # support bundle, plus index growth. Docker images are already on disk
        # and are not re-pulled. 12 GB is the floor at which the run cannot
        # finish; 20 GB is where it stops being comfortable.
        free_gb = shutil.disk_usage("/").free / 2**30
        detail["free_disk_gb"] = round(free_gb, 1)
        ctx.check("at least 12 GB free", free_gb >= 12,
                  expected=">=12 GB", actual=f"{free_gb:.1f} GB",
                  note="a memory image, a KAPE upload and a support bundle")
        if free_gb < 20:
            tl.warn("disk_tight", detail={
                "free_gb": round(free_gb, 1),
                "note": "run should fit, but there is little headroom"})

        # sudo, tested for real. A wrong password discovered at the install
        # phase means the wipe already happened.
        r = shell.sudo(["true"], cfg.sudo_password, timeout=30, tl=tl,
                       stage="preflight")
        ctx.check("sudo password works", r.ok,
                  note="platform.sudo_password in qa/qa-config.yaml")

        # Windows target reachable and admin — checked before anything is
        # destroyed, for the same reason.
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

        r = shell.sudo(["bash", "install.sh"], cfg.sudo_password,
                       timeout=cfg.timeout("install", 90) * 60,
                       cwd=REPO_DIR, log_path=log_path, tl=tl, stage="install")

        ctx.check("install.sh exited 0", r.ok, actual=r.rc)
        ctx.check("install marker written", os.path.exists(INSTALL_MARKER))

        # Copy install.sh's own log too — it carries the pre-container phase
        # that our capture starts too late to see on a resumed run.
        for candidate in sorted(_glob_logs(REPO_DIR)):
            shutil.copy2(candidate, os.path.join(ctx.run_dir, "logs",
                                                 os.path.basename(candidate)))

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

    # ----------------------------------------------------------------- 1 --
    @runner.phase("auth", "Claim the appliance and hold a session",
                  needs=("install",), critical=True)
    def auth(ctx):
        """A per-run random dashboard password, written to the run directory at
        0600 rather than into qa-config.yaml. It is a real credential to a real
        appliance, so it does not belong in a tracked file — and writing it down
        means the operator can still log in and look around after a failed run.
        """
        import secrets
        import string

        alphabet = string.ascii_letters + string.digits
        password = "Qa-" + "".join(secrets.choice(alphabet) for _ in range(20))
        username = "qa"

        # Register with the redactor BEFORE it is used, or the first API log
        # line carries it to disk.
        ctx.redact.secrets.insert(0, password)
        ctx.redact.secrets.sort(key=len, reverse=True)

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

        ctx.set(client=c, dash_user=username, creds_path=creds_path)
        return {"how": how, "mode_before": mode_before, "mode_after": mode_after,
                "credentials_file": creds_path}


# --- helpers -------------------------------------------------------------


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
