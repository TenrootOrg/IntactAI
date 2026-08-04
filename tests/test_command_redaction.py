"""A credential must never reach a log line, because those logs travel.

This was found in a real support bundle on a live box. Inside
containers/intact_backend.log:

    Running: docker exec -e IRIS_RESET_PW=123123 intact_iris_app python3 -c ...

The operator's IRIS administrator password, sitting in the one artifact the
platform builds specifically to be sent to other people.

The mechanism is a footgun worth understanding, because the call site was
trying to do the right thing. services/upgrade/iris.py builds
`docker exec -e IRIS_RESET_PW=<pw> ...` and calls run_command with
`logger=None`, clearly meaning "do not log this". But run_command's signature is
`logger: Callable = None` and its body does:

    log = logger or (lambda msg, level="info": print(f"[{level}] {msg}"))

so `logger=None` does not silence the echo — it routes it to print(), i.e.
stdout, i.e. `docker logs`, i.e. the support bundle. The one caller that asked
for silence got the loudest possible channel.

Truncation was not a mitigation either: the echo was `cmd[:80]` and the password
sat inside those 80 characters.

Nor is the bundle the only destination. add_log_to_run() persists to the SQLite
`workflows` table, and the `intact_workflow_runs` Elasticsearch index maps a
nested `logs` array — so the same string can land in two databases.

The fix redacts at the choke point in run_command, unconditionally, so a future
call site cannot opt out by forgetting. These tests pin that, and pin that
redaction does not mangle the ordinary commands the upgrade path depends on.

Run: docker exec intact_backend python3 /app/workdir/tests/test_command_redaction.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
BASE = os.path.join(REPO, "modules", "backend", "services", "upgrade", "base.py")


def _load():
    """Exec just the redaction helper.

    Importing services.upgrade.base drags in the whole upgrade stack (and opens
    the real database); redact_command is pure, so slice it out instead — same
    idiom as tests/test_llm_error_classification.py.
    """
    with open(BASE, "r", encoding="utf-8") as handle:
        src = handle.read()
    start = src.index("_SECRET_ARG_PATTERNS")
    end = src.index("def run_command(")
    namespace = {"re": re}
    exec(compile(src[start:end], "<base-slice>", "exec"), namespace)  # noqa: S102
    return namespace["redact_command"]


REDACT = _load()


# --- the exact line that leaked ----------------------------------------------


def test_the_iris_password_reset_no_longer_leaks():
    """Verbatim shape from the support bundle that exposed this."""
    cmd = ("docker exec -e IRIS_RESET_PW=123123 intact_iris_app python3 -c "
           "'import os;from flask_bcrypt import Bcrypt;print(1)'")
    out = REDACT(cmd)
    assert "123123" not in out, f"the password survived redaction: {out}"
    assert "[REDACTED]" in out
    # The command must still be recognisable to a human debugging the log.
    assert "docker exec" in out and "intact_iris_app" in out


def test_redaction_happens_before_truncation():
    """The echo is cmd[:80]. The leaked password was inside those 80 chars, so
    slicing is not a mitigation and the order matters."""
    cmd = "docker exec -e IRIS_RESET_PW=hunter2 intact_iris_app python3 -c 'x'"
    assert "hunter2" not in REDACT(cmd)[:80]


# --- the shapes credentials actually arrive in --------------------------------


def test_env_assignments_that_look_like_credentials_are_masked():
    for cmd, secret in (
        ("docker exec -e POSTGRES_PASSWORD=s3cr3t c psql", "s3cr3t"),
        ("docker exec -e IRIS_ADM_PASSWORD=letmein c sh", "letmein"),
        ("PGPASSWORD=topsecret psql -U iris -d iris_db", "topsecret"),
        ("docker exec -e OPENAI_API_KEY=sk-abc123 c python3", "sk-abc123"),
        ("docker exec -e GITHUB_TOKEN=ghp_zzz c sh", "ghp_zzz"),
        ("docker exec -e VELOX_PASSWORD=abc c sh", "abc"),
        ("docker exec -e IRIS_SECRET_KEY=deadbeef c sh", "deadbeef"),
        ("docker exec -e MY_CREDENTIAL=xyz c sh", "xyz"),
    ):
        out = REDACT(cmd)
        assert secret not in out, f"{secret!r} not masked in: {out}"


def test_flag_style_credentials_are_masked():
    for cmd, secret in (
        ("velociraptor user add admin --password hunter2", "hunter2"),
        ("some-cli --password=hunter2 --verbose", "hunter2"),
        ("curl -s https://x --token abcdef123456", "abcdef123456"),
        ("tool --api-key=sk-live-999", "sk-live-999"),
        ("tool --secret shhhh", "shhhh"),
    ):
        out = REDACT(cmd)
        assert secret not in out, f"{secret!r} not masked in: {out}"


def test_masking_is_case_insensitive():
    assert "nope" not in REDACT("docker exec -e iris_reset_pw=nope c sh")
    assert "nope" not in REDACT("tool --PASSWORD nope")


def test_multiple_secrets_in_one_command_are_all_masked():
    cmd = ("docker exec -e POSTGRES_PASSWORD=aaa -e IRIS_ADM_PASSWORD=bbb "
           "c sh --token ccc")
    out = REDACT(cmd)
    for secret in ("aaa", "bbb", "ccc"):
        assert secret not in out, f"{secret!r} survived in: {out}"


# --- and the ordinary commands must survive untouched ------------------------
#
# Over-redacting would blind the upgrade path's own diagnostics, which is how a
# safety measure turns into an outage nobody can debug.


def test_normal_upgrade_commands_are_not_mangled():
    for cmd in (
        "docker compose up -d --no-build backend tusd",
        "docker inspect -f '{{.Config.Image}}' intact_backend",
        "docker images intact-backend --format '{{.Repository}}:{{.Tag}}'",
        "tar -czf /data/out.tar.gz -C /tmp pkg",
        "docker exec intact_iris_db psql -U iris -d iris_db -c 'SELECT 1;'",
        "git pull origin development",
        "docker rmi intact-backend:intact-20260726",
    ):
        assert REDACT(cmd) == cmd, f"a harmless command was altered: {REDACT(cmd)}"


def test_a_non_secret_env_var_is_left_alone():
    """BACKEND_VERSION is an env assignment too, and the upgrade log needs it —
    the pattern must key on the NAME looking like a credential."""
    cmd = "BACKEND_VERSION=intact-20260730 docker compose up -d backend"
    assert REDACT(cmd) == cmd, f"a version pin was redacted: {REDACT(cmd)}"


def test_empty_and_none_are_safe():
    assert REDACT("") == ""
    assert REDACT(None) is None


# --- the wiring: the choke point must actually use it ------------------------


def test_run_command_redacts_its_echo():
    with open(BASE, "r", encoding="utf-8") as handle:
        src = handle.read()
    start = src.index("def run_command(")
    body = src[start:src.index("\ndef ", start + 10)]
    echo = [ln for ln in body.splitlines() if "Running:" in ln]
    assert echo, "run_command no longer echoes the command — did the line move?"
    for line in echo:
        assert "redact_command" in line, (
            f"run_command echoes the raw command, so any credential in it leaks "
            f"to stdout -> docker logs -> support bundle: {line.strip()}")


def test_redaction_is_unconditional():
    """Not gated behind a flag or a logger argument. The call site that leaked was
    the one that thought it had opted out."""
    with open(BASE, "r", encoding="utf-8") as handle:
        src = handle.read()
    start = src.index("def run_command(")
    body = src[start:src.index("\ndef ", start + 10)]
    echo = [ln for ln in body.splitlines() if "Running:" in ln][0]
    lowered = echo.lower()
    for gate in (" if ", "quiet", "verbose"):
        assert gate not in lowered, (
            f"the redaction looks conditional ({gate!r} in the echo line); it "
            f"must apply to every caller: {echo.strip()}")


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
