#!/usr/bin/env python3
"""Subscription-based LLM providers driven by a vendor CLI.

Some operators would rather spend an existing Codex/ChatGPT subscription than
provision a metered API key. Those subscriptions are only usable through the
vendor's own CLI, so for these providers intact installs the CLI, walks the
operator through a device-code login, and then shells out to it per request
instead of calling an HTTP API with a key.

Three deliberate design choices:

1. **Credentials live in the SQLite ``secrets`` table, never on disk.**
   ``secrets`` is the one table ``export_db()`` refuses to dump and the support
   bundle never collects, so an OAuth token cannot ride out of the box inside a
   backup, a DB export or a support archive the way a config value could. The
   CLI insists on a *directory* (``CODEX_HOME``) holding ``auth.json``, so we
   materialise that directory on tmpfs (/dev/shm) for the lifetime of one
   command and write any refreshed token straight back to the database. The
   token therefore only ever exists in RAM: nothing sensitive survives between
   calls, and nothing lands in the bind-mounted /app/data tree operators back up.

2. **The CLI binary is installed at runtime, not baked into the image.**
   It is a ~50 MB native binary needing internet to fetch; most deployments will
   never select this provider. It lands in /app/data (which persists across
   upgrades) because a binary is not a secret.

3. **Login is device-code, never a localhost callback.** The operator's browser
   is on their laptop, not on the intact host, so an OAuth redirect to
   127.0.0.1 inside a container can never complete. ``codex login --device-auth``
   prints a URL plus a short code that can be approved from any device.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from services.storage.secret_store import get_secret, set_secret, delete_secret

# The CLI binary persists across upgrades; /app/data is the bind-mounted,
# upgrade-surviving state dir. Not a secret, so a plain file is fine.
_CLI_ROOT = os.environ.get("INTACT_AGENTIC_CLI_ROOT", "/app/data/agentic_cli")
_BIN_DIR = os.path.join(_CLI_ROOT, "bin")
# Where the vendor installer unpacks the release. The launcher in _BIN_DIR is a
# symlink into this tree, so it is part of the *installation*, not credential
# state — no secrets land here (auth.json only ever exists in a tmpfs scratch
# home for the duration of one command).
_PKG_HOME = os.path.join(_CLI_ROOT, "pkg")

# provider id -> everything that differs between vendors. Adding Claude later
# means adding a second entry here plus a branch in the few places that name
# codex explicitly (install/login are vendor-specific by nature).
PROVIDERS = {
    "codex-subscription": {
        # Keep in step with the provider <option> in partials/settings.html —
        # this label is what the CLI panel shows once the provider is selected,
        # so a mismatch reads as two different providers.
        "label": "OpenAI (Subscription)",
        "binary": "codex",
        "secret_key": "codex_cli_auth",
        "home_env": "CODEX_HOME",
        "auth_file": "auth.json",
        # Deliberately empty: the models a subscription may use depend on the
        # account tier, and the CLI picks one the account is entitled to. Naming
        # a model here caused "The 'gpt-5-codex' model is not supported when
        # using Codex with a ChatGPT account." for ChatGPT-auth operators.
        "default_model": "",
        "installer": "https://github.com/openai/codex/releases/latest/download/install.sh",
    },
}


_INSTALL_TIMEOUT = 300
_LOGIN_URL_TIMEOUT = 60
_TEST_TIMEOUT = 120

# ---------------------------------------------------------------------------
# action log — what the operator sees under the Install / Connect / Test buttons
# ---------------------------------------------------------------------------
# Every step of every action lands here, including the exact CLI output on
# failure, so a support engineer can tell "no internet" from "vendor rejected
# the code" from "binary missing" without shelling into the container. Kept in
# memory (a rolling buffer per provider) because it is operational noise, not
# case evidence — and because it may quote CLI output, it must never be written
# somewhere a backup or support bundle would pick it up.
_LOG_CAP = 300
_logs = {}
_log_lock = threading.Lock()


def _log(provider, message, level="info", run_id=None):
    """Record one step. Goes to the Actions workflow log when a run is bound.

    Install / Configure / Test each run as a `settings` automation run so the
    operator watches them in Settings → Actions with the same log modal every
    other system operation uses, instead of a bespoke panel.
    """
    entry = {"ts": time.strftime("%H:%M:%S"), "level": level,
             "message": str(message)[:1000]}
    with _log_lock:
        buf = _logs.setdefault(provider, [])
        buf.append(entry)
        if len(buf) > _LOG_CAP:
            del buf[:len(buf) - _LOG_CAP]
    print(f"[SUB-CLI] {provider} {level}: {message}", flush=True)
    if run_id:
        try:
            from services.workflow_service import add_log_to_run
            add_log_to_run(run_id, str(message)[:1000], level)
        except Exception:  # noqa: BLE001 — logging must never break the action
            pass
    return entry


def _progress(run_id, pct, status="running"):
    """Mirror the house pattern: workflows move through `running` with a
    percentage so the Actions row shows a live bar instead of sitting at
    'pending' until the very end."""
    if not run_id:
        return
    try:
        from services.workflow_service import update_run_status
        update_run_status(run_id, status, progress=int(pct))
    except Exception:  # noqa: BLE001
        pass


def get_log(provider) -> list:
    with _log_lock:
        return list(_logs.get(provider, []))




def _check_internet(provider, what, run_id=None) -> bool:
    """Probe connectivity and log the outcome. Every network-touching action
    calls this first so 'it just failed' is never the whole story."""
    _log(provider, f"Checking internet connectivity before {what}…", run_id=run_id)
    try:
        from services.connectivity import has_internet
        ok = has_internet()
    except Exception as e:  # noqa: BLE001
        _log(provider, f"Connectivity probe itself failed: {e}", "warning", run_id)
        return True   # don't block on a broken probe; the action will report
    if ok:
        _log(provider, "Internet connectivity OK", "success", run_id)
    else:
        _log(provider,
             f"No internet connectivity — {what} needs to reach the vendor. "
             f"Check the network/proxy and try again.", "error", run_id)
    return ok


def is_subscription_provider(provider) -> bool:
    return str(provider or "") in PROVIDERS


def _spec(provider) -> dict:
    spec = PROVIDERS.get(str(provider or ""))
    if not spec:
        raise ValueError(f"Not a subscription provider: {provider!r}")
    return spec


# Search roots for a CLI somebody else installed. Module-level so they read as
# data, and so a test can point them at a sandbox instead of finding whatever is
# really on the build machine.
# THE HOST BRIDGE. The appliance no longer installs or signs in to codex — the
# operator does that themselves, on the host, the ordinary way. This process is
# in a container, so compose bind-mounts the two things it then needs, read-only
# and at neutral paths (mounting over /usr/local/bin would shadow the image's
# own python). Both resolve to an empty directory when the operator has no codex
# — an absent mount and an empty one are the same answer here, which is why
# nothing below has to care which it got.
# FIXED, and deliberately NOT read from the environment.
#
# INTACT_HOST_CODEX_PKG / INTACT_HOST_CODEX_HOME are the HOST-side sources of
# those mounts, written into modules/backend/.env for compose to expand. And
# compose passes .env through `env_file:`, so every one of those variables also
# lands in the container's environment. Reading them here therefore got the
# HOST path -- /usr/local/lib/node_modules, which does not exist in this image
# -- and discovery found nothing while the mount sat there working. Measured on
# a live appliance: the mount was present and readable at /host/node_modules,
# and _NPM_ROOTS came back ('/usr/local/lib/node_modules', ...) twice over.
#
# The destination is a contract between docker-compose.yaml and this module, not
# a setting. Tests override the module attributes directly.
#
# THREE ROOTS, and the point of the first two is that NOTHING IN THEIR PATH
# CHANGES WHEN CODEX IS UPGRADED:
#   /host/codex        the operator's ~/.codex — credential, and every release
#                      the official installer has ever fetched
#   /host/node_modules the npm global root, from `npm root -g`
#   /host/codex-pkg    whatever `command -v codex` resolved to, for an install in
#                      neither of those. This one CAN name a version
#                      (.../releases/0.149.1-.../), so it is the fallback and not
#                      the mechanism — an upgrade would leave it pointing at a
#                      release the operator no longer runs.
# Versions inside each root are handled by globs, never by a pinned path.
_HOST_PKG_DIR = "/host/codex-pkg"
_HOST_CODEX_HOME = "/host/codex"
_HOST_NPM_DIR = "/host/node_modules"

_NPM_ROOTS = (
    _HOST_NPM_DIR,
    "/usr/local/lib/node_modules",
    "/usr/lib/node_modules",
    os.path.expanduser("~/.npm-global/lib/node_modules"),
    os.path.expanduser("~/.nvm/versions/node/*/lib/node_modules"),
    "/opt/homebrew/lib/node_modules",
)
# Deliberately EMPTY, and not an oversight. This used to list /usr/local/bin,
# /usr/bin, ~/.local/bin and /opt/bin — every one of which is the CONTAINER's
# filesystem, not the host's. The operator's install can never be at any of them,
# so they could only ever produce a false positive from something inside the
# image, and they padded the "searched" list with six paths that were never
# candidates. The operator's copy arrives through the mounts below or not at all.
_BIN_SEARCH_DIRS: tuple = ()


def install_target_path(provider) -> str:
    """Where OUR installer puts it. Not where it might already be — see
    binary_path. Used to verify the install and to chmod what it wrote."""
    return os.path.join(_BIN_DIR, _spec(provider)["binary"])


def _npm_vendor_globs(binary):
    """Where `npm i -g @openai/codex` actually leaves a runnable binary.

    Measured on a box with a normal install, because the layout is not what the
    name suggests:

      /usr/local/bin/codex
        -> ../lib/node_modules/@openai/codex/bin/codex.js        (a NODE shim)
      /usr/local/lib/node_modules/@openai/codex/node_modules/
        @openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex
                                                                 (the real thing)

    The launcher on PATH is JavaScript. Finding it and exec'ing it needs a node
    runtime, which this image does not ship — so the vendored binary underneath
    is the one worth finding. It is a static-pie ELF and answers `--version` on
    its own (verified: codex-cli 0.147.0, no node involved).

    Globbed rather than listed: the platform triple and the package name both
    vary by arch, and a hardcoded x86_64 path would quietly find nothing on an
    arm64 appliance.
    """
    # THE OFFICIAL INSTALLER'S LAYOUT, which is a third one again:
    #
    #   curl -fsSL https://chatgpt.com/codex/install.sh | sh
    #     ~/.local/bin/codex                                        launcher symlink
    #     ~/.codex/packages/standalone/current       -> releases/<v>-<triple>
    #     ~/.codex/packages/standalone/releases/<v>-<triple>/bin/codex   the binary
    #
    # Globbed through releases/*, NEVER through `current`. `current` is an
    # ABSOLUTE symlink into the operator's home — /home/<them>/.codex/... — and
    # this process is in a container where that path does not exist, so it
    # resolves to nothing even though the file is right there under the mount.
    # Measured: `ls .../current/bin/codex` fails inside the container while
    # `ls .../releases/*/bin/codex` finds it and it runs (codex-cli 0.149.1).
    #
    # Under _HOST_CODEX_HOME because that is already mounted for the credential;
    # the binary happens to live inside the same directory, so this costs no
    # extra mount. The un-mounted local twin is listed too, for a box where this
    # module is not containerised.
    # THE MOUNTED PACKAGE ROOT comes first, and is the one that is meant to hit.
    # lib/config.sh resolved it by asking the operator's own shell where codex is
    # and following the symlinks to the real file — so it is whatever they
    # actually installed, not a layout we guessed. Both known shapes are checked
    # inside it, because "package root" means a different depth in each:
    #   standalone: <root>/bin/codex
    #   npm:        <root>/node_modules/@openai/codex-<arch>/vendor/<triple>/bin/codex
    yield f"{_HOST_PKG_DIR}/bin/{binary}"
    # The mount root IS the releases dir, not its parent. lib/config.sh
    # deliberately climbs out of the version component so that `codex upgrade`
    # does not need a re-stamp -- which leaves INTACT_HOST_CODEX_PKG pointing at
    #   ~/.codex/packages/standalone/releases
    # and made the pattern below expand to .../releases/releases/*/bin/codex.
    # Nothing could ever match it, so the whole codex-pkg mount was dead weight
    # for the standard standalone install and discovery survived only on the
    # separate ~/.codex home mount. This is the pattern that matches what is
    # actually mounted; the releases/ form stays for a root stamped one level up.
    yield f"{_HOST_PKG_DIR}/*/bin/{binary}"
    yield f"{_HOST_PKG_DIR}/releases/*/bin/{binary}"
    yield f"{_HOST_PKG_DIR}/node_modules/@openai/{binary}-*/vendor/*/bin/{binary}"
    # An operator-declared location (config.yaml `agentic.codex_path`) is mounted
    # at the same place, and can name a directory of any shape at all -- so the
    # binary may sit directly at the mount root with no layout around it.
    yield f"{_HOST_PKG_DIR}/{binary}"
    # The npm global root, asked of npm itself at stamp time rather than
    # assumed. Version-independent: the package directory keeps its name across
    # every upgrade, so this keeps working with no re-stamp.
    yield f"{_HOST_NPM_DIR}/@openai/{binary}/node_modules/@openai/{binary}-*/vendor/*/bin/{binary}"
    yield f"{_HOST_NPM_DIR}/@openai/{binary}/bin/{binary}"

    # Then the layouts, as a safety net for the case the resolution above cannot
    # cover: codex installed AFTER this appliance was last configured, so the
    # mount still points at the empty placeholder. ~/.codex is mounted regardless
    # (the credential lives there) and the standalone installer happens to put
    # the binary inside it, so that route keeps working with no re-stamp at all.
    for home in (_HOST_CODEX_HOME, os.path.expanduser(f"~/.{binary}")):
        yield f"{home}/packages/standalone/releases/*/bin/{binary}"

    for root in _NPM_ROOTS:
        # the vendored native binary (preferred — no runtime needed)
        yield f"{root}/@openai/{binary}/node_modules/@openai/{binary}-*/vendor/*/bin/{binary}"
        # and the shim, as a last resort: harmless when node is absent, since
        # _usable only reports it and exec would fail loudly rather than silently
        yield f"{root}/@openai/{binary}/bin/{binary}"


def _candidate_paths(provider):
    """Every place a usable CLI could be, best first.

    This used to be one hardcoded path, and the panel told operators who had
    just installed the CLI that it was not installed. It only ever looked in the
    directory OUR installer writes to, so an operator who installed codex the
    normal way — which puts it somewhere completely different — got a flat
    contradiction of what they could see in their own shell.

    Order is deliberate: the copy we manage wins, because that is the one the
    upgrade keeps current. A stray newer binary earlier in the list would
    silently outrank it and drift.

    USABLE is the operative word, and it is the part no path list can fix. This
    process runs inside the backend container, so it can only find and exec what
    is on the CONTAINER's filesystem. A CLI installed on the host is invisible
    here however hard we look — verified: /usr/local/lib/node_modules does not
    exist in this image. detect() says that in as many words rather than
    repeating "not installed" at someone looking at their own working install.
    """
    binary = _spec(provider)["binary"]
    seen = set()

    def _emit(c):
        if c and c not in seen:
            seen.add(c)
            return [c]
        return []

    out = list(_emit(install_target_path(provider)))
    for exact in _marked_live(provider):
        out += _emit(exact)
    out += _emit(shutil.which(binary))          # anything on the container's PATH
    for pattern in _npm_vendor_globs(binary):
        # Order here is only for the diagnostic "searched" list; binary_path
        # ranks the usable ones by mtime across every root.
        for hit in sorted(glob.glob(pattern)):
            out += _emit(hit)
    for d in _BIN_SEARCH_DIRS:
        out += _emit(os.path.join(os.path.expanduser(d), binary))
    out += _emit(os.path.expanduser(f"~/.{binary}/bin/{binary}"))
    return out


def _marked_live(provider):
    """The release the installer says is live, read rather than guessed.

    The standalone installer keeps a `current` symlink beside releases/ naming
    the release it just installed. The target is an ABSOLUTE host path, so it
    cannot be followed from inside this container — but its BASENAME is the
    exact answer, and that beats ranking files by mtime.

    Mtime is a guess about which file is newest; this is what the operator's own
    shell resolves. They agree almost always, and when they disagree the marker
    is right: `codex` on the host follows this symlink, so anything else would
    have the appliance running a different binary from the person supporting it.
    """
    binary = _spec(provider)["binary"]
    roots = (_HOST_PKG_DIR,
             os.path.dirname(_HOST_PKG_DIR),
             f"{_HOST_CODEX_HOME}/packages/standalone")
    seen = set()
    for root in roots:
        if not root or root in seen:
            continue
        seen.add(root)
        try:
            live = os.path.basename(os.readlink(os.path.join(root, "current")))
        except OSError:
            continue
        if live:
            yield os.path.join(root, "releases", live, "bin", binary)


def _mtime_or_zero(path):
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0


def _usable(path) -> bool:
    return bool(path) and os.path.isfile(path) and os.access(path, os.X_OK)


def binary_path(provider) -> str:
    """The CLI we would actually run.

    Two rules, in order, and the order is the point:

      1. WHAT THE INSTALLER SAYS IS LIVE. Its `current` marker names the release
         the operator's own `codex` resolves to. Reading it means the appliance
         and the person supporting it are running the same binary.

      2. Failing that, the NEWEST usable copy by mtime. A fallback, not the
         mechanism — npm leaves no marker and only ever keeps one copy, so there
         is nothing to disagree about there; this also covers a hand-placed
         binary. It is a guess, and it is last for that reason. Measured why it
         cannot be the only rule: `codex upgrade` writes a new release beside the
         old one, and list order alone kept the appliance on the old one.

    Falls back to the install target so a message that formats this path still
    names somewhere sensible when nothing is installed at all.
    """
    for exact in _marked_live(provider):
        if _usable(exact):
            return exact
    usable = [c for c in _candidate_paths(provider) if _usable(c)]
    if not usable:
        return install_target_path(provider)
    return max(usable, key=_mtime_or_zero)


def is_installed(provider) -> bool:
    return any(_usable(c) for c in _candidate_paths(provider))


# ---------------------------------------------------------------------------
# credential handling — the DB is the source of truth, tmpfs is scratch
# ---------------------------------------------------------------------------

# Which credential a materialised scratch home was filled from, keyed by its
# path. Read by _release_home, which must not copy a host credential into our
# database. Popped there, so it cannot grow.
_HOME_SOURCE: dict = {}


def host_credential_path(provider) -> str:
    """The operator's own auth.json, as mounted from their ~/.codex."""
    return os.path.join(_HOST_CODEX_HOME, _spec(provider)["auth_file"])


def _read_host_credential(provider):
    """Their credential, or None. Never raises: an unreadable or absent file is
    the ordinary state of a box whose operator has not signed in yet."""
    try:
        with open(host_credential_path(provider), encoding="utf-8") as fh:
            blob = fh.read().strip()
        return blob or None
    except OSError:
        return None


def has_credentials(provider) -> bool:
    """Either credential counts.

    The stored one is checked FIRST and deliberately. Appliances that signed in
    through the old in-app device-code flow have a working credential in the
    secret store and no ~/.codex on the host at all; preferring the host copy
    would sign them out on upgrade for no reason. New boxes have only the host
    copy. Both work, neither is migrated, and nothing has to be re-done.
    """
    return bool(get_secret(_spec(provider)["secret_key"])) or bool(_read_host_credential(provider))


# tmpfs is SMALL (64MB by default in Docker) and these homes are ~15MB each, so a
# leaked one is not a tidiness problem -- four of them wedge every model call on the
# box with "No space left on device" while df reports tens of GB free. They leak
# because codex leaves a background child holding the dir open, so the rmtree in
# _release_home fails; it used to fail SILENTLY under ignore_errors=True.
_HOME_PREFIX = "intact-cli-home-"
_HOME_ABANDONED_SECONDS = 30 * 60


def _sweep_abandoned_homes(parent):
    """Remove homes no live call owns. Never touches one still registered in
    _HOME_SOURCE, so a long-running call in another thread is safe."""
    if not parent:
        return
    now = time.time()
    try:
        names = os.listdir(parent)
    except OSError:
        return
    for name in names:
        if not name.startswith(_HOME_PREFIX):
            continue
        path = os.path.join(parent, name)
        if path in _HOME_SOURCE:
            continue                      # a live call owns it
        try:
            if now - os.stat(path).st_mtime < _HOME_ABANDONED_SECONDS:
                continue                  # young enough to belong to a call in flight
        except OSError:
            continue
        shutil.rmtree(path, ignore_errors=True)
        print(f"[SUB-CLI] swept abandoned credential home {name} "
              f"(tmpfs is small; a leaked home wedges every later call)", flush=True)


def _materialize_home(provider):
    """Write the stored credential into a fresh private dir and return its path.

    Caller MUST call _release_home() to persist refreshes and shred the dir.
    """
    spec = _spec(provider)
    # /dev/shm is tmpfs: the credential exists only in RAM, never on persistent
    # storage, so it cannot be swept into a backup or a support bundle. It also
    # avoids the CLI's own refusal to use a "/tmp" path as its home ("Refusing
    # to create helper binaries under temporary dir"), which /tmp triggers.
    parent = "/dev/shm" if os.path.isdir("/dev/shm") else None
    _sweep_abandoned_homes(parent)
    home = tempfile.mkdtemp(prefix="intact-cli-home-", dir=parent)
    os.chmod(home, 0o700)
    blob = get_secret(spec["secret_key"])
    _HOME_SOURCE[home] = "store" if blob else "host"
    if not blob:
        blob = _read_host_credential(provider)
    if blob:
        auth = os.path.join(home, spec["auth_file"])
        with open(auth, "w") as f:
            f.write(blob)
        os.chmod(auth, 0o600)
    return home


def _release_home(provider, home, persist=True):
    """Persist a refreshed token back to the DB, then remove the scratch dir.

    The CLI rotates its access token in place, so skipping the write-back would
    silently expire a login held in our own store after a few hours.

    IT MUST NOT WRITE BACK A CREDENTIAL THAT CAME FROM THE HOST. Doing so copies
    the operator's login into our database, where has_credentials then prefers it
    forever — so the appliance quietly forks off its own snapshot of their
    identity. If they later sign out, or sign in as somebody else, the box keeps
    using the old one and nothing on any screen says why. The host copy is theirs
    and stays the source of truth; ours is only written back when it was ours to
    begin with.
    """
    spec = _spec(provider)
    source = _HOME_SOURCE.pop(home, "store")
    try:
        if persist and source == "store":
            auth = os.path.join(home, spec["auth_file"])
            if os.path.isfile(auth):
                with open(auth) as f:
                    blob = f.read()
                if blob.strip() and blob != (get_secret(spec["secret_key"]) or ""):
                    set_secret(spec["secret_key"], blob)
    except Exception as e:  # noqa: BLE001 — never fail a request over this
        print(f"[SUB-CLI] token write-back failed: {e}", flush=True)
    finally:
        # NOT ignore_errors: this is exactly where the leak was invisible. A child
        # the CLI left running holds the dir open, rmtree fails, and 15MB of a 64MB
        # tmpfs is gone with nothing said. Retry once, then say so -- the sweeper
        # above will collect it later, but the log has to show it happened.
        shutil.rmtree(home, ignore_errors=True)
        if os.path.isdir(home):
            try:
                shutil.rmtree(home)
            except OSError as e:
                print(f"[SUB-CLI] could not remove credential home {home}: {e} "
                      f"-- tmpfs leak; will be swept on a later call", flush=True)


# Where the "do it manually" escape hatch tells the operator to point the CLI.
# Used when the in-app device flow cannot reach the vendor (egress rules, proxy)
# and the login is driven from a shell instead.
MANUAL_HOME = os.path.join(_CLI_ROOT, "manual")


def import_manual_credential(provider) -> dict:
    """Adopt a credential produced by a manual `codex login` on the host.

    The file is read, stored in the `secrets` table and then deleted, so the
    token ends up in the same place as an in-app login and does not linger on
    the bind-mounted data volume where a backup could pick it up.
    """
    spec = _spec(provider)
    path = os.path.join(MANUAL_HOME, spec["auth_file"])
    if not os.path.isfile(path):
        return {"success": False,
                "error": f"nothing to import — {path} does not exist. Run the "
                         f"command above first, and approve the code it prints."}
    try:
        with open(path) as f:
            blob = f.read()
        json.loads(blob)          # refuse to store something that is not the CLI's file
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"{path} is not readable JSON: {e}"}

    if not set_secret(spec["secret_key"], blob):
        return {"success": False, "error": "could not write the credential to the database"}
    try:
        os.remove(path)
        shutil.rmtree(MANUAL_HOME, ignore_errors=True)
    except Exception:  # noqa: BLE001
        pass
    _log(provider, "Imported a manually-created login into the database")
    d = detect(provider)
    if not d.get("authenticated"):
        return {"success": False,
                "error": f"the credential was imported but the CLI still reports: "
                         f"{d.get('detail') or 'not logged in'}"}
    return {"success": True, "detail": d.get("detail", "connected")}


def forget_credentials(provider) -> bool:
    """Disconnect: drop the stored token. The CLI binary is left installed."""
    return delete_secret(_spec(provider)["secret_key"])


def _env_for(provider, home) -> dict:
    env = dict(os.environ)
    env[_spec(provider)["home_env"]] = home
    # Both the managed dir AND wherever the binary actually resolved: the CLI
    # shells out to helper binaries that sit beside itself, so a copy found
    # somewhere other than _BIN_DIR needs its own directory on PATH too.
    _own = os.path.dirname(binary_path(provider))
    _pre = [_BIN_DIR] + ([_own] if _own and _own != _BIN_DIR else [])
    env["PATH"] = os.pathsep.join(_pre + [env.get("PATH", "")])
    # keep the CLI from trying to be interactive or open a browser
    env["CI"] = "1"
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"
    return env


def _run(provider, args, home, timeout, stdin_data=None):
    """Run the CLI with a materialised credential dir. Returns CompletedProcess."""
    return subprocess.run(
        [binary_path(provider)] + list(args),
        env=_env_for(provider, home),
        cwd=tempfile.gettempdir(),
        input=stdin_data,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


# ---------------------------------------------------------------------------
# detect — what the UI polls
# ---------------------------------------------------------------------------

def _mount_report() -> dict:
    """What the three host mounts actually contain, seen from in here.

    An EMPTY mount is the signature of both ways this goes wrong, and neither is
    visible from the host — out there the paths in modules/backend/.env look
    perfectly correct:
      * the appliance was configured before codex was installed, so .env still
        names the empty placeholder install.sh created; or
      * .env was corrected afterwards but the container was never recreated, so
        it is still running the mounts it was born with.
    Measured on a live box: .env read /home/<op>/.codex/packages/standalone/
    releases while /host/codex-pkg was the empty placeholder.
    """
    out = {}
    for p in (_HOST_CODEX_HOME, _HOST_PKG_DIR, _HOST_NPM_DIR):
        try:
            if not os.path.isdir(p):
                out[p] = "not mounted"
                continue
            n = len(os.listdir(p))
            out[p] = f"{n} entr{'y' if n == 1 else 'ies'}" if n else "mounted but EMPTY"
        except Exception as e:                       # noqa: BLE001
            out[p] = f"unreadable ({type(e).__name__})"
    return out


def detect(provider) -> dict:
    """Report installed / authenticated state. Cheap: no model call, no network.

    Shape: {provider, installed, version, authenticated, auth_mode, detail}
    """
    spec = _spec(provider)
    out = {
        "provider": provider,
        "label": spec["label"],
        "installed": False,
        "version": None,
        "authenticated": False,
        "auth_mode": None,
        "detail": "",
    }
    if not is_installed(provider):
        # Name the paths. An operator who has just installed the CLI reads a bare
        # "not installed" as the product being broken — and from where they are
        # standing they are right, because their copy is usually on the HOST and
        # this runs in a container that cannot see or execute it.
        out["searched"] = _candidate_paths(provider)
        out["mounts"] = _mount_report()
        out["detail"] = (
            f"{spec['binary']} is not installed, or this appliance cannot see it. "
            f"Install it on the host, then sign in with `{spec['binary']} login`. "
            f"If it IS installed there and working in your own shell, this "
            f"container's mounts are stale — run `sudo ./scripts/refresh_codex.sh` "
            f"on the host. Restarting the backend cannot fix it: docker resolves "
            f"bind mounts when a container is CREATED, so a restart faithfully "
            f"reproduces the mounts it already had. For an install somewhere the "
            f"search cannot reach, set `agentic.codex_path` in config.yaml to the "
            f"binary (or its directory) and run that same script.")
        return out
    out["installed"] = True
    out["path"] = binary_path(provider)

    home = _materialize_home(provider)
    try:
        try:
            v = _run(provider, ["--version"], home, 20)
            out["version"] = (v.stdout or v.stderr or "").strip()[:60] or None
        except Exception:
            pass

        if not has_credentials(provider):
            out["detail"] = (
                f"{spec['binary']} {out['version'] or ''} found, but nobody is signed in. "
                f"Run `{spec['binary']} login` on the host as the user who owns this "
                f"appliance, then press Re-check.").replace("  ", " ")
            return out
        out["credential_source"] = (
            "store" if get_secret(spec["secret_key"]) else "host")

        # `codex login status` is a pure local credential check: exit 0 when
        # logged in, 1 when not. No tokens spent.
        try:
            r = _run(provider, ["login", "status"], home, 30)
            out["authenticated"] = (r.returncode == 0)
            text = _plain((r.stdout or "") + (r.stderr or "")).strip()
            out["detail"] = text[:200] or ("connected" if out["authenticated"] else "not logged in")
            m = re.search(r"(ChatGPT|API key|apikey)", text, re.I)
            if m:
                out["auth_mode"] = m.group(1)
        except subprocess.TimeoutExpired:
            out["detail"] = "login status check timed out"
        except Exception as e:  # noqa: BLE001
            out["detail"] = f"status check failed: {e}"
    finally:
        # a status check can refresh the token — keep the DB current
        _release_home(provider, home)
    return out


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------

def _resolve_installer_url(spec, provider, run_id=None):
    """Turn the moving `latest` URL into an immutable per-tag one.

    `/releases/latest/download/install.sh` is a stable URL with unstable
    content: the bytes change on every upstream release, with no version in the
    URL and nothing to compare against. Resolving to a concrete tag makes the
    artifact immutable, so the digest logged next to it means something.

    Falls back to the original URL on ANY failure — GitHub's unauthenticated
    API allows 60 requests/hour per IP, and a shared or busy egress address
    would otherwise lose the ability to install at all. A moving URL whose
    digest is recorded is still a large improvement over a pipe into a shell.

    Returns ``(url, human_version)``.
    """
    api = "https://api.github.com/repos/openai/codex/releases/latest"
    try:
        r = subprocess.run(["curl", "-fsSL", "--max-time", "20", api],
                           capture_output=True, text=True, timeout=30)
        tag = (json.loads(r.stdout or "{}") or {}).get("tag_name") if r.returncode == 0 else None
    except Exception:  # noqa: BLE001 — resolution is best-effort by design
        tag = None

    if not tag or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(tag)):
        # Also the guard against a hostile tag: it is interpolated into a URL,
        # and although argv is a list (so it can never become shell syntax), a
        # tag containing "../" or a scheme would still redirect the download.
        _log(provider, "Could not resolve the latest release tag "
                       "(offline, rate-limited, or an unexpected value) — "
                       "using the rolling installer URL.", "warning", run_id)
        return spec["installer"], "latest (unresolved)"
    return (f"https://github.com/openai/codex/releases/download/{tag}/install.sh",
            str(tag))


def install(provider, run_id=None) -> dict:
    """Download and install the vendor CLI. Requires internet.

    Every step is written to the action log so the panel under the button
    explains what happened — especially on failure.
    """
    spec = _spec(provider)
    _progress(run_id, 5)
    _log(provider, f"Installing the {spec['binary']} CLI into {_BIN_DIR}...", run_id=run_id)

    _progress(run_id, 10)
    if not _check_internet(provider, "installing the CLI", run_id):
        return {"success": False,
                "error": "No internet connectivity — installing the CLI needs "
                         "to download it from the vendor.",
                "log": get_log(provider)}

    try:
        os.makedirs(_BIN_DIR, exist_ok=True)
    except Exception as e:  # noqa: BLE001
        _log(provider, f"Could not create {_BIN_DIR}: {e}", "error", run_id)
        return {"success": False, "error": f"could not create {_BIN_DIR}: {e}",
                "log": get_log(provider)}
    _progress(run_id, 25)
    _log(provider, f"Downloading the installer from {spec['installer']}...", run_id=run_id)
    # The vendor installer honours CODEX_INSTALL_DIR / CODEX_NON_INTERACTIVE,
    # so we can place the binary in our own tree without touching $HOME.
    env = dict(os.environ)
    env["CODEX_INSTALL_DIR"] = _BIN_DIR
    env["CODEX_NON_INTERACTIVE"] = "1"
    # The installer unpacks the release into $CODEX_HOME/packages/... and makes
    # $CODEX_INSTALL_DIR/codex a SYMLINK into it, so this path must be stable and
    # must NOT be the per-call scratch home we use at run time (that lives in
    # /tmp and is deleted after every command — it would break the symlink).
    env["CODEX_HOME"] = _PKG_HOME
    # Download, RECORD, then execute — instead of piping the network into a
    # shell. This container holds a read-write Docker socket, so whatever this
    # script does runs as root on the host; "we ran whatever was served at the
    # time and kept no record of it" is not a defensible position for a
    # forensics platform.
    #
    # Three changes, none of which alter what a working install does:
    #   - resolve `latest` to a concrete tag so the artifact is immutable, and
    #     fall back to the moving URL if the API is unreachable or rate-limited
    #     (60 req/hr unauthenticated — a hard failure here would break installs
    #     on a busy egress IP for no security gain)
    #   - fetch to a temp file and log its SHA-256 with the resolved version, so
    #     "what exactly did this box execute?" is answerable afterwards
    #   - no `sh -c`, no f-string building a command; argv is a list, so a tag
    #     coming from a network response can never become shell syntax
    url, resolved = _resolve_installer_url(spec, provider, run_id)
    tmp_dir = tempfile.mkdtemp(prefix="codex_install_")
    script = os.path.join(tmp_dir, "install.sh")
    try:
        try:
            dl = subprocess.run(["curl", "-fsSL", "-o", script, url],
                                env=env, capture_output=True, text=True, timeout=120)
            if dl.returncode != 0 or not os.path.exists(script):
                err = _plain(dl.stderr or "").strip()[:200] or f"curl exit {dl.returncode}"
                _log(provider, f"Could not download the installer: {err}", "error", run_id)
                return {"success": False, "error": f"installer download failed: {err}",
                        "log": get_log(provider)}
            digest = hashlib.sha256(open(script, "rb").read()).hexdigest()
            _log(provider,
                 f"Installer {resolved} downloaded — sha256 {digest}. Executing.",
                 run_id=run_id)
            r = subprocess.run(["sh", script],
                               env=env, capture_output=True, text=True,
                               timeout=_INSTALL_TIMEOUT)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    except subprocess.TimeoutExpired:
        msg = f"installer timed out after {_INSTALL_TIMEOUT}s"
        _log(provider, msg + " — slow link or a blocking proxy?", "error", run_id)
        return {"success": False, "error": msg, "log": get_log(provider)}
    except Exception as e:  # noqa: BLE001
        _log(provider, f"Installer could not be started: {e}", "error", run_id)
        return {"success": False, "error": f"installer failed to start: {e}",
                "log": get_log(provider)}

    _progress(run_id, 80)
    tail = _plain((r.stdout or "") + (r.stderr or "")).strip()[-800:]
    for line in [l for l in tail.splitlines() if l.strip()][-12:]:
        _log(provider, line.strip(), run_id=run_id)
    # install_target_path, NOT binary_path: this is asking "did the installer
    # produce the file it was told to produce". Accepting any candidate would
    # let an unrelated copy already on PATH report a failed download as a
    # successful install, and the next upgrade would have nothing to update.
    if not _usable(install_target_path(provider)):
        _log(provider,
             f"Installer exited {r.returncode} but {install_target_path(provider)} is "
             f"missing — the download or unpack step failed.", "error", run_id)
        return {"success": False,
                "error": f"installer finished (exit {r.returncode}) but "
                         f"{install_target_path(provider)} is missing. Output: {tail}",
                "log": get_log(provider)}
    try:
        os.chmod(install_target_path(provider), 0o755)
    except Exception:
        pass
    _progress(run_id, 95)
    d = detect(provider)
    _log(provider, f"✓ CLI installed: {d.get('version') or 'version unknown'}",
         "success", run_id)
    _log(provider, "Next: click Connect to sign in with your subscription.", run_id=run_id)
    return {"success": True, "version": d.get("version"), "output": tail,
            "log": get_log(provider)}


# ---------------------------------------------------------------------------
# login (device code) — browser may be on a different machine
# ---------------------------------------------------------------------------

# The CLI emits ANSI colour even with NO_COLOR/TERM=dumb set, and the escape
# sequence sits immediately after the URL — parsing without stripping it yields
# "https://…/device\x1b[0m". Strip first, then match.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
# Real device codes look like S6G3-P2UQL — 4 then 5 chars, not 4+4.
_CODE_RE = re.compile(r"\b([A-Z0-9]{4}-[A-Z0-9]{4,8})\b")


def _plain(text) -> str:
    return _ANSI_RE.sub("", text or "")


class SubscriptionCLIError(RuntimeError):
    """CLI invocation failed. ``reason`` mirrors llm_sim's reason codes."""

    def __init__(self, message, reason="llm_error"):
        super().__init__(message)
        self.reason = reason


def _vendor_message(text) -> str:
    """Pull the human sentence out of the CLI's JSON event stream.

    A failure arrives as newline-delimited events whose `error.message` is
    itself a JSON string, so the readable sentence sits two levels deep:
        {"type":"turn.failed","error":{"message":"{\"error\":{\"message\":
         \"The 'x' model is not supported ...\"}}"}}
    Logging the raw blob (truncated mid-token) tells an operator nothing, so dig
    out the sentence and fall back to the raw tail only if we cannot find one.
    """
    best = ""
    for line in (text or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        msg = ((ev.get("error") or {}).get("message")
               if isinstance(ev.get("error"), dict) else None)
        if not isinstance(msg, str):
            continue
        # the message is frequently another JSON document
        inner = msg.strip()
        if inner.startswith("{"):
            try:
                doc = json.loads(inner)
                deep = (doc.get("error") or {}).get("message")
                if isinstance(deep, str) and deep.strip():
                    inner = deep.strip()
            except Exception:
                pass
        if inner:
            best = inner
    return best


def _classify(text) -> str:
    t = (text or "").lower()
    if "not supported when using" in t or "model is not supported" in t \
            or ("invalid_request_error" in t and "model" in t):
        return "model_unsupported"
    if "not logged in" in t or "unauthor" in t or "authentication_failed" in t \
            or "login" in t and "required" in t:
        return "cli_not_authenticated"
    if "rate limit" in t or "429" in t or "usage limit" in t:
        return "rate_limited"
    if "timed out" in t or "timeout" in t:
        return "timeout"
    if "network" in t or "connection" in t or "dns" in t or "offline" in t:
        return "no_internet"
    return "llm_error"


def run_prompt(provider, prompt, system_prompt=None, model=None, timeout=None) -> dict:
    """Send one prompt through the CLI. Returns {text, in_tokens, out_tokens}.

    Raises SubscriptionCLIError with a reason code the fusion layer already
    knows how to render.
    """
    spec = _spec(provider)
    if not is_installed(provider):
        raise SubscriptionCLIError(
            f"{spec['label']}: the {spec['binary']} CLI is not installed. "
            f"Install it in Settings → Agentic.", "cli_not_installed")
    if not has_credentials(provider):
        raise SubscriptionCLIError(
            f"{spec['label']}: not connected. Sign in from Settings → Agentic.",
            "cli_not_authenticated")

    from services.agentic.constants import ONLINE_LLM_TIMEOUT_SECONDS
    timeout = int(timeout or ONLINE_LLM_TIMEOUT_SECONDS)
    full = f"{system_prompt}\n\n{prompt}" if system_prompt else prompt

    home = _materialize_home(provider)
    out_file = os.path.join(home, "last_message.txt")
    # No PROMPT argument: `codex exec` reads the instructions from stdin, which
    # is what we want (report prompts reach hundreds of KB and would risk ARG_MAX
    # on the command line). Passing "-" would be taken as a literal prompt.
    args = ["exec", "--json", "--skip-git-repo-check", "--sandbox", "read-only",
            "-o", out_file]
    if model:
        args += ["-m", str(model)]

    try:
        r = _run(provider, args, home, timeout, stdin_data=full)
        combined = _plain((r.stdout or "") + "\n" + (r.stderr or "")).strip()
        text = ""
        if os.path.isfile(out_file):
            with open(out_file) as f:
                text = f.read().strip()
        in_tok, out_tok = _usage_from_jsonl(r.stdout)

        if r.returncode != 0 and not text:
            vendor = _vendor_message(r.stdout or "")
            raise SubscriptionCLIError(
                f"{spec['label']}: {vendor}" if vendor else
                f"{spec['label']} CLI failed (exit {r.returncode}): "
                f"{combined[-400:] or 'no output'}",
                _classify(vendor or combined))
        if not text:
            # fall back to the JSON event stream if -o produced nothing
            text = _text_from_jsonl(r.stdout)
        if not text:
            vendor = _vendor_message(r.stdout or "")
            raise SubscriptionCLIError(
                f"{spec['label']} returned no content: {vendor or combined[-300:]}",
                _classify(vendor or combined))
        return {"text": text, "in_tokens": in_tok, "out_tokens": out_tok}
    except subprocess.TimeoutExpired:
        raise SubscriptionCLIError(
            f"{spec['label']} CLI timed out after {timeout}s", "timeout")
    finally:
        _release_home(provider, home)


def _usage_from_jsonl(stdout):
    """Pull token counts out of the CLI's newline-delimited JSON events."""
    in_tok = out_tok = 0
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        usage = ev.get("usage") or (ev.get("turn") or {}).get("usage") or {}
        if isinstance(usage, dict) and usage:
            in_tok = int(usage.get("input_tokens") or usage.get("prompt_tokens") or in_tok or 0)
            out_tok = int(usage.get("output_tokens") or usage.get("completion_tokens") or out_tok or 0)
    return in_tok, out_tok


def _text_from_jsonl(stdout):
    """Last-resort extraction of the assistant's final message."""
    best = ""
    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        item = ev.get("item") or {}
        if isinstance(item, dict):
            t = item.get("text") or item.get("content")
            if isinstance(t, str) and t.strip():
                best = t.strip()
        msg = ev.get("message") or ev.get("last_agent_message")
        if isinstance(msg, str) and msg.strip():
            best = msg.strip()
    return best


def list_models(provider) -> list:
    """Return the model catalog the CLI itself publishes for this account.

    `codex debug models` renders the catalog as JSON. This is the authoritative
    list for the CLI transport — unlike the vendor's web /models endpoint, whose
    slugs `codex exec -m` rejects outright.
    """
    if not is_installed(provider):
        raise SubscriptionCLIError(
            f"{_spec(provider)['binary']} CLI is not installed", "cli_not_installed")
    if not has_credentials(provider):
        raise SubscriptionCLIError("not connected", "cli_not_authenticated")

    home = _materialize_home(provider)
    try:
        r = _run(provider, ["debug", "models"], home, 60)
        raw = _plain(r.stdout or "")
        start = raw.find("{")
        if start < 0:
            raise SubscriptionCLIError(
                f"the CLI returned no catalog: "
                f"{(_plain(r.stderr or '') or raw)[-300:]}", _classify(raw))
        try:
            data = json.loads(raw[start:])
        except Exception as e:
            raise SubscriptionCLIError(f"could not parse the catalog: {e}", "llm_error")
        return data.get("models") or []
    except subprocess.TimeoutExpired:
        raise SubscriptionCLIError("listing models timed out", "timeout")
    finally:
        _release_home(provider, home)


def test_connection(provider, run_id=None) -> dict:
    """Round-trip a trivial prompt so the operator can prove it works."""
    spec = _spec(provider)
    started = time.time()
    _progress(run_id, 10)
    _log(provider, f"Testing the {spec['label']} connection...", run_id=run_id)

    d = detect(provider)
    if not d["installed"]:
        _log(provider, f"{spec['binary']} CLI is not installed — run the "
                       f"Install action first.", "error", run_id)
        return {"success": False, "stage": "install",
                "error": f"{spec['binary']} CLI is not installed"}
    _progress(run_id, 30)
    _log(provider, f"✓ CLI present ({d.get('version') or 'version unknown'})",
         "success", run_id)
    if not d["authenticated"]:
        _log(provider, f"Not signed in: {d.get('detail') or 'no credential stored'} "
                       f"— run the Configure action first.", "error", run_id)
        return {"success": False, "stage": "auth",
                "error": d.get("detail") or "not connected"}
    _log(provider, "✓ Credential accepted by the CLI", "success", run_id)

    _progress(run_id, 50)
    if not _check_internet(provider, "the test call", run_id):
        return {"success": False, "stage": "network",
                "error": "No internet connectivity — the model call cannot leave this host."}

    _progress(run_id, 70)
    _log(provider, "Sending a one-line prompt to the model...", run_id=run_id)
    try:
        res = run_prompt(provider, "Reply with exactly: OK", model=None,
                         timeout=_TEST_TIMEOUT)
        ms = int((time.time() - started) * 1000)
        _progress(run_id, 95)
        _log(provider, f"✓ Model replied in {ms} ms: "
                       f"{(res.get('text') or '')[:120]!r} "
                       f"({res.get('in_tokens', 0)} in / {res.get('out_tokens', 0)} out tokens)",
             "success", run_id)
        return {"success": True, "stage": "prompt", "elapsed_ms": ms,
                "reply": (res.get("text") or "")[:200],
                "in_tokens": res.get("in_tokens", 0),
                "out_tokens": res.get("out_tokens", 0)}
    except SubscriptionCLIError as e:
        _log(provider, f"Test failed ({e.reason}): {e}", "error", run_id)
        return {"success": False, "stage": "prompt", "reason": e.reason, "error": str(e),
                "elapsed_ms": int((time.time() - started) * 1000)}
    except Exception as e:  # noqa: BLE001
        _log(provider, f"Test failed unexpectedly: {e}", "error", run_id)
        return {"success": False, "stage": "prompt", "error": str(e),
                "elapsed_ms": int((time.time() - started) * 1000)}


# ---------------------------------------------------------------------------
# Actions-tab workflows
# ---------------------------------------------------------------------------
# Each operator action is a `settings` automation run so it shows up in
# Settings → Actions with the same live log modal every other system operation
# uses. The routes create the run, hand back its id, and the UI jumps to the
# Actions tab; these bodies run in a daemon thread.

WORKFLOW_NAMES = {
    "install":   "Agentic - Subscription Connector [Codex] - Install Codex CLI",
    "configure": "Agentic - Subscription Connector [Codex] - Configure Codex CLI",
    "test":      "Agentic - Subscription Connector [Codex] - Test Codex CLI",
}


# Run ids whose worker thread is alive *in this process*. A pending row that is
# NOT in here has no worker left (the backend restarted); one that IS here is
# being superseded by a newer attempt. The two deserve different explanations.
_active_runs = set()


def is_run_active(run_id) -> bool:
    with _log_lock:
        return run_id in _active_runs


def _mark_active(run_id):
    with _log_lock:
        _active_runs.add(run_id)


def _finish(run_id, ok, summary):
    with _log_lock:
        _active_runs.discard(run_id)
    try:
        from services.workflow_service import update_run_status
        update_run_status(run_id, "completed" if ok else "failed",
                          progress=100 if ok else None,
                          error=None if ok else summary)
    except Exception as e:  # noqa: BLE001
        print(f"[SUB-CLI] could not close run {run_id}: {e}", flush=True)


def sweep_orphaned_runs() -> int:
    """Fail every connector run left pending/running by a dead process.

    Called once at backend boot. These workflows live on daemon threads, so a
    restart (upgrade, crash, compose recreate) takes the worker AND the CLI
    child with it — including any device login that was mid-approval. The row
    would otherwise sit at 'running' forever and the operator would approve a
    code that no longer has a process behind it.
    """
    try:
        from services import workflow_service as ws
        sid = ws._system_case_id()
        runs = ws.get_automation_runs_by_case(sid) if sid else []
    except Exception as e:  # noqa: BLE001
        print(f"[SUB-CLI] orphan sweep could not read runs: {e}", flush=True)
        return 0
    ours = set(WORKFLOW_NAMES.values())
    n = 0
    for r in runs:
        if r.get("name") not in ours or r.get("status") not in ("pending", "running"):
            continue
        try:
            ws.add_log_to_run(
                r["run_id"],
                "Interrupted: the backend restarted while this workflow was "
                "running, so it could not finish. Any sign-in code it issued is "
                "no longer valid — start the action again.", "error")
            ws.update_run_status(r["run_id"], "failed",
                                 error="interrupted by a backend restart")
            n += 1
        except Exception:  # noqa: BLE001
            pass
    if n:
        print(f"[SUB-CLI] closed {n} orphaned connector run(s) after restart", flush=True)
    return n


# INSTALL AND SIGN-IN LIVED HERE, and were removed.
#
# run_install_workflow fetched the vendor installer over the internet and ran it
# into a directory of ours; run_configure_workflow drove a device-code sign-in
# and stored the credential in our database. Both are gone, along with
# login_start / login_poll / login_cancel / disconnect / import_credential and
# the install/login HTTP routes.
#
# Neither was the appliance's business. Installing third-party software on the
# host behind a button in a web panel, and holding somebody's ChatGPT
# credential, are things an operator does better and more visibly themselves —
# and the install half only ever worked on a box with outbound internet, which a
# DFIR appliance frequently is not. What replaced them is discovery: find the
# codex the operator installed (_candidate_paths) and read the credential they
# already have (_read_host_credential), both mounted read-only into this
# container by modules/backend/docker-compose.yaml.
#
# WORKFLOW_NAMES still carries "install" and "configure". That is not a leftover:
# sweep_orphaned_runs matches on those names to close rows left behind by the old
# flow on an appliance that is upgrading. Dropping them would strand those rows
# "running" forever.

def run_test_workflow(run_id, provider):
    """Background body for the Test action."""
    _mark_active(run_id)
    try:
        _progress(run_id, 1)
        res = test_connection(provider, run_id=run_id)
        _finish(run_id, bool(res.get("success")), res.get("error", ""))
    except Exception as e:  # noqa: BLE001
        _log(provider, f"Test workflow crashed: {e}", "error", run_id)
        _finish(run_id, False, str(e))
