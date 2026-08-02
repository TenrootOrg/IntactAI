"""The QA harness must not leak the credentials it is given.

qa/qa-config.yaml is tracked in git AND holds this appliance's sudo password
plus the Windows target's Administrator password. Three things must hold or
that arrangement becomes a credential disclosure:

  1. The COMMITTED copy is always blank.
  2. The working copy is 0600.
  3. Every value in it is stripped from logs, bundles and the report — which is
     the artifact a human actually shares.

Run: python3 tests/test_qa_config_and_redaction.py
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "qa"))

from lib import config as qa_config     # noqa: E402
from lib import redact as qa_redact     # noqa: E402

QA_CONFIG = os.path.join(REPO, "qa", "qa-config.yaml")


# --- what is committed ---------------------------------------------------------


def _git(*args):
    """Run a git command, or return None if git cannot answer.

    The CI test gate runs this suite inside python:3.11-slim, which ships no
    git binary — so these must degrade to "cannot check here" rather than
    raising FileNotFoundError. The check still runs where it matters: on a
    developer box and on the appliance, both of which have git, and the
    pre-commit sanitizer is the actual control.
    """
    try:
        r = subprocess.run(["git", "-C", REPO] + list(args),
                           capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return None
    return r


def _committed_qa_config():
    r = _git("show", "HEAD:qa/qa-config.yaml")
    if r is None or r.returncode != 0:
        return None
    return r.stdout


def test_the_committed_qa_config_has_no_credentials():
    """The whole reason this file can be tracked at all."""
    body = _committed_qa_config()
    if body is None:
        return          # not committed yet
    import yaml
    cfg = yaml.safe_load(body) or {}
    for section, keys in (("platform", ("host", "sudo_user", "sudo_password")),
                          ("windows", ("host", "username", "password"))):
        for key in keys:
            val = (cfg.get(section) or {}).get(key)
            assert not val, \
                f"the COMMITTED qa-config.yaml has {section}.{key} populated " \
                f"— a credential is on GitHub"


def test_the_qa_config_is_gitignored_nowhere():
    """It must stay tracked; gitignoring it would mean a clone has no file to
    edit, which is the mistake config.yaml.example made."""
    r = _git("check-ignore", "-q", "qa/qa-config.yaml")
    if r is None:
        return          # no git binary (CI container) — nothing to check
    assert r.returncode != 0, "qa/qa-config.yaml is gitignored"


def test_the_sanitizer_covers_the_qa_config():
    sanitizer = os.path.join(REPO, "scripts", "git-hooks", "sanitize-config-yaml.sh")
    with open(sanitizer, encoding="utf-8") as fh:
        body = fh.read()
    assert "qa/qa-config.yaml" in body, \
        "the pre-commit sanitizer no longer blanks the QA config"


def test_run_output_never_lands_inside_the_repo():
    """Phase 0a deletes the repo. Results written inside it would be destroyed
    by the run that produced them."""
    cfg = qa_config.load(require=False)
    out = os.path.realpath(cfg.output_dir)
    assert not out.startswith(os.path.realpath(REPO) + os.sep), \
        f"run output_dir {out} is inside the repo, which phase 0a wipes"


def test_the_tracked_default_carries_no_username():
    """A tracked default must not bake one operator's home directory in.

    Checks parsed VALUES, not the file text. An earlier version searched the
    raw body and matched the comment that *explains* this rule ("`~` rather
    than a spelt-out /home/<user>") — a test that fails on its own
    documentation trains people to delete the documentation.
    """
    body = _committed_qa_config()
    if body is None:
        return
    import yaml

    def walk(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                yield from walk(v, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from walk(v, f"{path}[{i}]")
        elif isinstance(node, str):
            yield path, node

    for path, val in walk(yaml.safe_load(body) or {}):
        assert "/home/" not in val, \
            f"the tracked qa-config.yaml hardcodes a home directory at " \
            f"{path}={val!r}; use ~ instead"


# --- permissions ---------------------------------------------------------------


def test_loading_tightens_the_file_to_0600():
    """A clone arrives 0644 because git cannot store 0600. The harness must fix
    that on first run rather than leaving a sudo password world-readable."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("platform: {host: h, sudo_user: u, sudo_password: p}\n"
                 "windows: {host: h, username: u, password: p}\n")
        path = fh.name
    try:
        os.chmod(path, 0o644)
        qa_config.load(path)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"config left at {oct(mode)} after load"
    finally:
        os.unlink(path)


# --- validation ----------------------------------------------------------------


def test_a_blank_config_fails_with_a_useful_message():
    """The shipped state. Failing with a KeyError here would waste the
    operator's time before the run even starts."""
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("platform:\n  host: ''\nwindows:\n  host: ''\n")
        path = fh.name
    try:
        try:
            qa_config.load(path)
            assert False, "a blank config was accepted"
        except qa_config.ConfigError as exc:
            msg = str(exc)
            for field in ("platform.sudo_password", "windows.password"):
                assert field in msg, f"error does not name {field}: {msg}"
            assert "QA_SUDO_PASS" in msg, "error does not mention the env override"
    finally:
        os.unlink(path)


def test_env_vars_override_the_file():
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("platform: {host: '1.1.1.1', sudo_user: u, sudo_password: ''}\n"
                 "windows: {host: '2.2.2.2', username: u, password: p}\n")
        path = fh.name
    os.environ["QA_SUDO_PASS"] = "from-env"
    try:
        cfg = qa_config.load(path)
        assert cfg.sudo_password == "from-env"
        assert cfg.platform_host == "1.1.1.1", "env override clobbered file values"
    finally:
        del os.environ["QA_SUDO_PASS"]
        os.unlink(path)


def test_secrets_are_ordered_longest_first():
    """Redacting a short secret that is a substring of a longer one first would
    leave a fragment behind — and one that LOOKS redacted, so nobody rechecks."""
    cfg = qa_config.QAConfig({
        "platform": {"host": "10.0.0.1", "sudo_user": "adm",
                     "sudo_password": "pw"},
        "windows": {"host": "10.0.0.2", "username": "administrator",
                    "password": "pwlonger"},
    }, "<test>")
    lengths = [len(s) for s in cfg.secrets()]
    assert lengths == sorted(lengths, reverse=True), cfg.secrets()


# --- redaction -----------------------------------------------------------------


def _redactor():
    return qa_redact.Redactor(["10RootRulez", "vagrant", "192.168.120.128"])


def test_known_secrets_are_removed():
    out = _redactor().redact(
        "sudo -S <<< '10RootRulez'\nssh vagrant@192.168.120.128\n")
    for leaked in ("10RootRulez", "vagrant", "192.168.120.128"):
        assert leaked not in out, f"'{leaked}' survived:\n{out}"


def test_unknown_credential_shapes_are_caught_by_pattern():
    """The known-value layer cannot catch a PAT the harness never saw."""
    # Assembled at runtime rather than written as a literal: a real-shaped
    # ghp_ string in this file trips the repo's own gitleaks gate, which would
    # block every commit that touches the tests. The fixture has to look like a
    # PAT to the redactor without looking like one to the scanner.
    fake_pat = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    out = _redactor().redact(
        f"github_token: '{fake_pat}'\n"
        "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig\n")
    assert fake_pat not in out, out
    assert "abcdefghij" not in out, out
    assert "eyJhbGciOiJIUzI1NiJ9" not in out, out


def test_a_longer_secret_is_redacted_before_a_shorter_substring():
    r = qa_redact.Redactor(["pw", "pwlonger"])
    out = r.redact("password=pwlonger")
    assert "pwlonger" not in out and "longer" not in out, out


def test_redaction_walks_nested_json():
    """Phase results are JSON; a secret in a nested detail field is just as
    published as one in the report body."""
    out = _redactor().redact_structure(
        {"phase": "install", "detail": {"cmd": ["sudo", "-S", "10RootRulez"]}})
    assert "10RootRulez" not in repr(out), out


def test_the_canary_is_actually_removed():
    """The self-test the harness runs before building any report. Redaction
    failure is silent by construction — the report looks fine either way."""
    text = qa_redact.canary_text()
    assert qa_redact.canary_survives(text), "canary helper is broken"
    cleaned = qa_redact.Redactor([]).redact(text)
    assert not qa_redact.canary_survives(cleaned), \
        f"the canary survived redaction:\n{cleaned}"


def test_redaction_does_not_swallow_the_rest_of_the_line():
    """An over-broad pattern that ate whole lines would destroy the diagnostic
    value of the logs the QA exists to collect."""
    out = _redactor().redact(
        "2026-08-02 12:00:01 INFO password=hunter2 container=intact_backend ok\n")
    assert "hunter2" not in out
    assert "container=intact_backend ok" in out, out
    assert out.endswith("\n"), "redaction ate the line ending"


def test_bytes_survive_a_round_trip():
    out = _redactor().redact(b"login 10RootRulez done")
    assert isinstance(out, bytes)
    assert b"10RootRulez" not in out and b"done" in out


def test_short_values_are_not_treated_as_secrets():
    """A 1-2 char 'secret' would match everywhere and redact the whole log."""
    r = qa_redact.Redactor(["a", "ok"])
    out = r.redact("a container is ok and available")
    assert out == "a container is ok and available", out


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1
            print(f"FAIL {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
