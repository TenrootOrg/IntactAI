"""Load and validate qa/qa-config.yaml.

One file holds everything a run needs that cannot be derived: the appliance's
address and sudo credentials, and the Windows target's address and
Administrator credentials. Everything else has a shipped default.

Two rules this module enforces, both of which exist because of what a QA run
produces:

  * The file must be 0600. It holds a sudo password, and a run directory full
    of memory images and support bundles is already the most sensitive material
    this platform ever holds — a world-readable password file alongside it is
    not a risk worth taking. Git cannot store 0600 (only 100644/100755), so a
    fresh clone arrives 0644; this tightens it on first run rather than
    complaining about something the operator did not do.

  * The secret VALUES are collected into `secrets()` so the redactor can strip
    them from every log, bundle and report the run emits. A password that
    reaches the report is a password that reaches whoever the report is shared
    with.
"""

import os
import stat

import yaml

# Anchored to the package root (the directory holding lib/), NOT to the repo.
#
# run_qa.py copies the whole qa/ tree to ~/.qa-runner/<run-id>/ and re-execs
# from there, so the directory is not always called "qa". Deriving the path by
# walking up three levels and appending "qa/" worked in the repo and looked for
# ~/.qa-runner/qa/qa-config.yaml after relocation — which does not exist, so
# every relocated run died before it started.
PACKAGE_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PATH = os.path.join(PACKAGE_ROOT, "qa-config.yaml")

# Environment overrides. The config file is the normal path; these exist so a
# run can be driven without a filled-in file (a scheduled job, a second
# operator on a shared checkout) and so a credential can be supplied without
# ever being written to disk.
#
# Deliberately env vars and not command-line flags: argv is world-readable in
# /proc on this box, and on the Windows side it lands in the event log that
# this QA then collects via KAPE, ingests into Timesketch, fuses into the Case
# and packages into the support bundle — carrying the credential through the
# entire pipeline the harness exists to test.
ENV_OVERRIDES = {
    ("platform", "host"): "QA_PLATFORM_HOST",
    ("platform", "sudo_user"): "QA_SUDO_USER",
    ("platform", "sudo_password"): "QA_SUDO_PASS",
    ("platform", "repo_dir"): "QA_REPO_DIR",
    ("windows", "host"): "QA_WIN_HOST",
    ("windows", "username"): "QA_WIN_USER",
    ("windows", "password"): "QA_WIN_PASS",
    ("run", "linux_client"): "QA_LINUX_CLIENT",
    ("run", "feature_sweep"): "QA_FEATURE_SWEEP",
    ("run", "pipelines"): "QA_PIPELINES",
    ("run", "scenario"): "QA_SCENARIO",
    ("run", "upgrade_to"): "QA_UPGRADE_TO",
    ("run", "upgrade_package"): "QA_UPGRADE_PACKAGE",
}

# Split in two because a Windows endpoint is a property of the PROFILE, not of
# the harness. A CI runner has no Windows box and never will: it enrols the
# Velociraptor Linux client on the appliance itself instead. Demanding all six
# meant the harness could not start at all without credentials for a machine
# that is not part of the run.
PLATFORM_REQUIRED = (
    ("platform", "host"),
    ("platform", "sudo_user"),
    ("platform", "sudo_password"),
)

WINDOWS_REQUIRED = (
    ("windows", "host"),
    ("windows", "username"),
    ("windows", "password"),
)

REQUIRED = PLATFORM_REQUIRED + WINDOWS_REQUIRED

# Which fields are credentials, for redaction. `host` is topology rather than a
# secret, but it is in the sanitizer's blank list and a report is a shareable
# artifact, so it is redacted too.
#
# DELIBERATELY the union, not PLATFORM_REQUIRED. Redaction must not narrow when
# validation does: a Windows password that is set but not *required* is still a
# password, and this repo is public. Tying this to whichever half a given run
# happens to demand would silently stop stripping the other half.
SECRET_FIELDS = REQUIRED


def _as_bool(value):
    """YAML booleans and env-var strings, resolved the same way.

    ENV_OVERRIDES injects raw strings, and `bool("false")` is True — so a
    QA_FEATURE_SWEEP=false meant to turn the sweep OFF would turn it on. Anything
    not recognisably false is false only if it is empty; the usual suspects are
    spelled out so "0", "no" and "off" behave the way whoever typed them meant."""
    if isinstance(value, str):
        return value.strip().lower() not in ("", "0", "false", "no", "off")
    return bool(value)


class ConfigError(Exception):
    """Raised for anything that makes a run impossible. Always names the file,
    the field, and how to fix it — a QA harness that fails with a KeyError has
    wasted the operator's time before the run even starts."""


class QAConfig:
    def __init__(self, data, path):
        self._data = data
        self.path = path

    # --- accessors -------------------------------------------------------

    def get(self, *keys, default=None):
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    @property
    def platform_host(self):
        return self.get("platform", "host")

    @property
    def sudo_user(self):
        return self.get("platform", "sudo_user")

    @property
    def sudo_password(self):
        return self.get("platform", "sudo_password")

    @property
    def windows_host(self):
        return self.get("windows", "host")

    @property
    def windows_user(self):
        return self.get("windows", "username")

    @property
    def windows_password(self):
        return self.get("windows", "password")

    @property
    def ssh_port(self):
        return int(self.get("windows", "ssh_port", default=22))

    @property
    def windows_enabled(self):
        """Is there a Windows endpoint in this run at all?

        All three values present means yes. All three blank means a Linux-only
        profile (CI, or an operator without a lab box) — the Windows phases
        simply do not register, and their dependants report as "not reached"
        rather than failing for a machine that was never part of the run.

        A PARTLY filled block is neither, and is treated as an error by load():
        two of three set is a typo or a half-finished edit, and silently running
        without Windows would hide it."""
        return all(str(self.get(s, k) or "").strip() for s, k in WINDOWS_REQUIRED)

    @property
    def output_dir(self):
        return os.path.expanduser(
            self.get("run", "output_dir", default="~/qa-runs"))

    @property
    def llm_summary(self):
        return bool(self.get("run", "llm_summary", default=False))

    @property
    def keep_memory(self):
        return bool(self.get("run", "keep_memory", default=False))

    @property
    def repo_dir(self):
        """Where the platform is installed — the tree install.sh runs from.

        Not a preference: get it wrong and the harness wipes and reinstalls a
        directory nothing is running from, then asserts against whatever
        appliance is actually up, passing or failing for reasons unrelated to
        the code under test."""
        return self.get("platform", "repo_dir", default="") or ""

    @property
    def cloud_tests(self):
        """Run the AWS/Azure cloud-module assertions.

        OFF by default and deliberately so. The cloud phase asserts on the
        aws_sigma rule pack and the o365rc image, neither of which this QA
        profile installs -- so with them enabled on a DFIR-only box every
        assertion fails for the wrong reason and buries the failures that
        matter. Written now so the coverage exists the moment a cloud-enabled
        box is available to point it at."""
        return bool(self.get("run", "cloud_tests", default=False))

    @property
    def linux_client(self):
        """Enrol the Velociraptor LINUX client on the appliance host itself.

        The appliance becomes its own endpoint. That is the only way a run with
        no lab machine gets a real `C.<hex>` client, and therefore the only way
        the collection paths get exercised at all."""
        return _as_bool(self.get("run", "linux_client", default=False))

    @property
    def feature_sweep(self):
        """Drive the backend's HTTP surface and assert on the answers."""
        return _as_bool(self.get("run", "feature_sweep", default=False))

    @property
    def pipelines(self):
        """Run each feature's LIGHTWEIGHT blueprint end to end.

        Separate from feature_sweep because it is a different kind of test and a
        different cost: the sweep is seconds of HTTP, this dispatches real
        collections and real detection runs and takes minutes."""
        return _as_bool(self.get("run", "pipelines", default=False))

    @property
    def scenario(self):
        """Which install/upgrade path this run is testing.

        One scenario per job, because container names, volumes and host ports
        are global — two appliances cannot share a machine. The scenario also
        decides which phases register at all, so a run only ever contains the
        phases it can actually satisfy."""
        return (self.get("run", "scenario", default="") or "").strip()

    @property
    def upgrade_to(self):
        """The release tag this scenario upgrades to. Empty = install only."""
        return (self.get("run", "upgrade_to", default="") or "").strip()

    @property
    def upgrade_package(self):
        """A package on disk to upgrade FROM, for the air-gapped routes."""
        return (self.get("run", "upgrade_package", default="") or "").strip()

    def timeout(self, stage, default=30):
        """Minutes to wait for a slow stage before calling it failed."""
        return int(self.get("run", "timeouts", stage, default=default))

    def secrets(self):
        """Every value the redactor must strip from logs, bundles and reports.

        Returned newest-first by length so that redacting the longest match
        first cannot leave a fragment of a longer secret behind after a shorter
        one that happens to be a substring has been replaced.
        """
        vals = set()
        for section, key in SECRET_FIELDS:
            v = self.get(section, key)
            if isinstance(v, str) and v.strip():
                vals.add(v.strip())
        return sorted(vals, key=len, reverse=True)


# --- loading ---------------------------------------------------------------


def _tighten_permissions(path):
    """Force 0600. Returns True if it had to change something."""
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if mode & 0o077:
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise ConfigError(
                f"{path} is mode {oct(mode)} and cannot be tightened to 0600 "
                f"({exc}). It holds a sudo password; fix the ownership before "
                f"running QA.")
        return True
    return False


def load(path=None, require=True):
    """Read qa-config.yaml, apply env overrides, validate.

    `require=False` skips the completeness check — used by tooling that wants
    the run settings without needing the credentials (e.g. the report writer
    resolving output_dir).
    """
    path = path or os.environ.get("QA_CONFIG") or DEFAULT_PATH

    if not os.path.exists(path):
        raise ConfigError(
            f"{path} not found.\n"
            f"It is tracked in git, so a clone should have it. If this is a "
            f"partial checkout, restore it with:\n"
            f"    git checkout -- qa/qa-config.yaml")

    tightened = _tighten_permissions(path)

    with open(path, encoding="utf-8") as fh:
        try:
            data = yaml.safe_load(fh) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"{path} is not valid YAML: {exc}")

    if not isinstance(data, dict):
        raise ConfigError(f"{path} must be a YAML mapping, got {type(data).__name__}")

    for (section, key), env in ENV_OVERRIDES.items():
        val = os.environ.get(env)
        if val:
            data.setdefault(section, {})[key] = val

    cfg = QAConfig(data, path)
    cfg.permissions_tightened = tightened

    if require:
        # Platform values are always required — there is no run without an
        # appliance. Windows values are required only if the block is PARTLY
        # filled: all-blank means "Linux-only profile", which is a legitimate
        # and now-common way to run, while two-of-three is a typo that would
        # otherwise silently downgrade the run to Linux-only and hide it.
        need = list(PLATFORM_REQUIRED)
        win_set = [(s, k) for s, k in WINDOWS_REQUIRED
                   if str(cfg.get(s, k) or "").strip()]
        if win_set:
            need += list(WINDOWS_REQUIRED)

        missing = [(s, k) for s, k in need
                   if not str(cfg.get(s, k) or "").strip()]
        if missing:
            lines = [f"{path} is missing required values:", ""]
            for section, key in missing:
                lines.append(f"    {section}.{key}"
                             f"   (or set ${ENV_OVERRIDES[(section, key)]})")
            if any(s == "windows" for s, _ in missing):
                lines += [
                    "",
                    "The windows block is PARTLY filled, so it is being treated "
                    "as a Windows run.",
                    "Leave all three blank for a Linux-only run — the Windows "
                    "phases then do not",
                    "register, and their dependants report as not reached "
                    "instead of failing.",
                ]
            lines += [
                "",
                "Fill them in and re-run. Your working copy is never committed:",
                "the pre-commit hook rewrites the STAGED copy back to blanks, so",
                "these values stay on this machine only.",
                "",
                "Confirm the hook is installed:  git config core.hooksPath",
                "  expected: scripts/git-hooks   (install.sh sets this, or run",
                "  scripts/install-git-hooks.sh)",
            ]
            raise ConfigError("\n".join(lines))

    return cfg
