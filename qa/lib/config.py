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

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))
DEFAULT_PATH = os.path.join(REPO_ROOT, "qa", "qa-config.yaml")

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
    ("windows", "host"): "QA_WIN_HOST",
    ("windows", "username"): "QA_WIN_USER",
    ("windows", "password"): "QA_WIN_PASS",
}

REQUIRED = (
    ("platform", "host"),
    ("platform", "sudo_user"),
    ("platform", "sudo_password"),
    ("windows", "host"),
    ("windows", "username"),
    ("windows", "password"),
)

# Which fields are credentials, for redaction. `host` is topology rather than a
# secret, but it is in the sanitizer's blank list and a report is a shareable
# artifact, so it is redacted too.
SECRET_FIELDS = REQUIRED


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
    def output_dir(self):
        return os.path.expanduser(
            self.get("run", "output_dir", default="~/qa-runs"))

    @property
    def llm_summary(self):
        return bool(self.get("run", "llm_summary", default=False))

    @property
    def keep_memory(self):
        return bool(self.get("run", "keep_memory", default=False))

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
        missing = [(s, k) for s, k in REQUIRED
                   if not str(cfg.get(s, k) or "").strip()]
        if missing:
            lines = [f"{path} is missing required values:", ""]
            for section, key in missing:
                lines.append(f"    {section}.{key}"
                             f"   (or set ${ENV_OVERRIDES[(section, key)]})")
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
