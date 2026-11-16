"""Module passwords in the backend: where they come from, and that they never leak.

- config.py takes them from the stores (ELASTIC_PASSWORD / TIMESKETCH_PASSWORD,
  env_file from modules/<m>/secrets/creds.env), the old .env names second, and
  NEVER a literal default (it used to be '123123').
- support bundle + live log redaction also catch `-u user:pass` and every stored
  value BY VALUE, label or no label.
- VolWeb's password is the secrets file, not config.yaml.
- the default-password marker the upgrade writes is reported as-is.
- the LLM CLI (a third-party binary) never gets a tool password in its env.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_BACKEND = os.path.join(_ROOT, "modules/backend")
for _p in (_HERE, _BACKEND):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402
try:
    import flask  # noqa: F401
except ImportError:
    _optional_deps.stub("flask")        # route modules import it at the top
try:
    import werkzeug.security  # noqa: F401
except ImportError:
    # auth_service imports it; the hash scheme is not under test here.
    import types
    _sec = types.ModuleType("werkzeug.security")
    _sec.generate_password_hash = lambda pw: "x$" + pw
    _sec.check_password_hash = lambda h, pw: h == "x$" + pw
    sys.modules["werkzeug"] = types.ModuleType("werkzeug")
    sys.modules["werkzeug"].security = _sec
    sys.modules["werkzeug.security"] = _sec
from services import support_bundle as sb  # noqa: E402
from services import live_logs  # noqa: E402

ES_PW = "StoredElastic9Xy"
IRIS_PW = "IrisAdmin12345Q"
VOLWEB_PW = "VolwebAdmin777Z"


def _box(root):
    """A fake appliance tree with the private stores lib/secrets.sh writes."""
    def w(rel, text):
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(text)
    w("modules/elk/secrets/creds.env", f"ELASTIC_PASSWORD={ES_PW}\nKIBANA_PASSWORD=KibanaSys4567AB\n")
    w("modules/iris/secrets/IRIS_ADM_PASSWORD", IRIS_PW + "\n")
    w("modules/volweb/secrets/ADMIN_PASSWORD", VOLWEB_PW)
    w("modules/portainer/secrets/admin_password", "short1")                      # under the floor
    w("modules/nginx/secrets/key.pem", "-----BEGIN KEY-----\nAAAABBBBCCCCDDDD\n-----END KEY-----\n")


def _config(env, workdir):
    """config.py's resolved credentials, imported fresh in a clean process."""
    code = ("import json, config; print(json.dumps([config.ELASTICSEARCH_CONFIG['password'], "
            "config.TIMESKETCH_CONFIG['password']]))")
    base = {k: v for k, v in os.environ.items()
            if k not in ("ELASTIC_PASSWORD", "ELASTICSEARCH_PASSWORD", "TIMESKETCH_PASS",
                         "TIMESKETCH_PASSWORD")}
    r = subprocess.run([sys.executable, "-c", code], cwd=_BACKEND, capture_output=True, text=True,
                       env={**base, "INTACT_PATH": workdir, **env}, timeout=60)
    if r.returncode:
        raise AssertionError(r.stderr)
    return json.loads(r.stdout.strip().splitlines()[-1])


class ConfigCredentials(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        self.empty = tempfile.mkdtemp()

    def test_store_names_win_over_old_env_names(self):
        es, ts = _config({"ELASTIC_PASSWORD": "fromStore1", "ELASTICSEARCH_PASSWORD": "oldEnv1",
                          "TIMESKETCH_PASSWORD": "tsStore1", "TIMESKETCH_PASS": "tsOld1"}, self.empty)
        self.assertEqual((es, ts), ("fromStore1", "tsStore1"))

    def test_old_env_names_still_work_on_an_unmigrated_box(self):
        es, ts = _config({"ELASTICSEARCH_PASSWORD": "oldEnv1", "TIMESKETCH_PASS": "tsOld1"}, self.empty)
        self.assertEqual((es, ts), ("oldEnv1", "tsOld1"))

    def test_no_literal_default_when_nothing_is_configured(self):
        es, ts = _config({}, self.empty)
        self.assertEqual((es, ts), ("", ""))   # was '123123' for Timesketch

    def test_running_backend_reads_the_elk_store_from_disk(self):
        # mid-upgrade: the env is blank, the store has just been written
        _box(self.td)
        es, _ = _config({}, self.td)
        self.assertEqual(es, ES_PW)

    def test_no_123123_literal_left_in_config_py(self):
        with open(os.path.join(_BACKEND, "config.py")) as f:
            code = "\n".join(ln for ln in f if not ln.lstrip().startswith("#"))
        self.assertNotIn("'123123'", code)


class Redaction(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.mkdtemp()
        _box(self.td)
        self.vals = sb.known_secret_values(self.td)

    def test_values_come_from_every_store_and_skip_short_and_multiline(self):
        self.assertIn(ES_PW, self.vals)
        self.assertIn("KibanaSys4567AB", self.vals)
        self.assertIn(IRIS_PW, self.vals)
        self.assertIn(VOLWEB_PW, self.vals)
        self.assertNotIn("short1", self.vals)
        self.assertFalse(any("BEGIN" in v or "AAAABBBB" in v for v in self.vals))

    def test_a_bare_value_is_redacted_without_any_label(self):
        out = sb.redact_line(f"connect failed for {ES_PW} at host; iris={IRIS_PW}x", self.vals)
        self.assertNotIn(ES_PW, out)
        self.assertNotIn(IRIS_PW, out)
        self.assertIn("connect failed for [REDACTED] at host", out)

    def test_curl_user_pass_forms(self):
        for line in ("curl -s -u elastic:hunter2xyz http://x",  # gitleaks:allow (fixture)
                     "curl --user elastic:hunter2xyz http://x",  # gitleaks:allow
                     "curl --user=elastic:hunter2xyz http://x",  # gitleaks:allow
                     "curl -u 'elastic:hunter2xyz' http://x"):  # gitleaks:allow
            out = sb.redact_line(line)
            self.assertNotIn("hunter2xyz", out, line)
            self.assertIn("elastic:[REDACTED]", out, line)

    def test_uid_gid_and_plain_flags_are_left_alone(self):
        for line in ("docker run -u 1000:1000 img", "docker exec -u root c"):
            self.assertEqual(sb.redact_line(line), line)

    def test_redact_file_uses_the_stored_values(self):
        p = os.path.join(self.td, "log.txt")
        with open(p, "w") as f:
            f.write(f"ok line\nauth as elastic with {ES_PW} failed\n")
        with mock.patch.dict(os.environ, {"INTACT_PATH": self.td}):
            self.assertEqual(sb._redact_file(p), 1)
        with open(p) as f:
            self.assertNotIn(ES_PW, f.read())

    def test_live_log_lines_are_redacted_by_value(self):
        text = f"2026-10-04T07:16:26.5Z volweb login {VOLWEB_PW} rejected\n"
        with mock.patch.dict(os.environ, {"INTACT_PATH": self.td}):
            logs, _ = live_logs.parse(text)
        self.assertEqual(logs[0]["message"], "volweb login [REDACTED] rejected")


class VolWebPassword(unittest.TestCase):
    def test_secrets_file_not_config_yaml(self):
        from services.memory import volweb_client as vc
        td = tempfile.mkdtemp()
        _box(td)
        with mock.patch.dict(os.environ, {"INTACT_PATH": td}), \
                mock.patch.object(vc, "_config_yaml_volweb", lambda k: "123123"), \
                mock.patch.object(vc, "_config_value", lambda key, default=None: default):
            self.assertEqual(vc._volweb_pass(), VOLWEB_PW)


class DefaultPasswordMarker(unittest.TestCase):
    def setUp(self):
        # routes/__init__.py imports every blueprint (and more of flask): load this one alone.
        spec = importlib.util.spec_from_file_location(
            "security_routes_under_test", os.path.join(_BACKEND, "routes/security_routes.py"))
        self.r = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.r)
        self.td = tempfile.mkdtemp()
        self.p = os.path.join(self.td, "default-passwords.json")

    def test_missing_marker_means_none(self):
        self.assertEqual(self.r.default_passwords_in_use(self.p)["modules"], [])

    def test_marker_modules_are_reported(self):
        with open(self.p, "w") as f:
            json.dump({"modules": ["elk", "timesketch", "volweb"], "since": "2026-11-15T10:00:00Z"}, f)
        got = self.r.default_passwords_in_use(self.p)
        self.assertEqual(got, {"modules": ["elk", "timesketch", "volweb"], "rotated": [],
                               "since": "2026-11-15T10:00:00Z"})

    def test_rotated_modules_are_reported(self):
        with open(self.p, "w") as f:
            json.dump({"modules": [], "rotated": ["portainer", "velociraptor", 7, ""],
                       "since": "2026-11-15T10:00:00Z"}, f)
        got = self.r.default_passwords_in_use(self.p)
        self.assertEqual(got["rotated"], ["portainer", "velociraptor"])
        self.assertEqual(got["modules"], [])
        with open(self.p, "w") as f:
            json.dump({"modules": "elk", "rotated": None}, f)        # wrong shapes
        self.assertEqual(self.r.default_passwords_in_use(self.p),
                         {"modules": [], "rotated": [], "since": None})

    def test_corrupt_marker_says_so(self):
        with open(self.p, "w") as f:
            f.write("{half")
        got = self.r.default_passwords_in_use(self.p)
        self.assertEqual(got["modules"], [])
        self.assertIn("error", got)

    def test_endpoint_is_behind_the_login_gate(self):
        from services import auth_service
        self.assertIsNotNone(auth_service.gate_decision(
            "/api/security/default-passwords", "GET", "10.0.0.5", {}))
        self.assertNotIn("/api/security/default-passwords", auth_service.EXEMPT_PATHS)


class CliEnvironment(unittest.TestCase):
    """The backend env holds every tool's password (compose env_file); the codex
    CLI and its downloaded installer must not inherit any of them."""
    SECRETS = {"ELASTIC_PASSWORD": "e", "TIMESKETCH_PASSWORD": "t", "KIBANA_PASSWORD": "k",
               "GITHUB_TOKEN": "g", "OPENAI_API_KEY": "o", "AZURE_CLIENT_SECRET": "a",
               "aws_credential_file": "c", "TIMESKETCH_PASS": "p"}
    KEEP = {"PATH": "/usr/bin", "HOME": "/root", "LANG": "C.UTF-8", "HTTPS_PROXY": "http://p:3128",
            "no_proxy": "localhost"}

    def test_secrets_never_reach_the_child_env(self):
        import types
        src = os.path.join(_BACKEND, "services/agentic/subscription_cli.py")
        with open(src, encoding="utf-8") as f:
            code = f.read()
        store = types.ModuleType("services.storage.secret_store")
        store.get_secret = store.set_secret = store.delete_secret = lambda *a, **k: None
        with mock.patch.dict(sys.modules, {"services.storage.secret_store": store}):
            mod = types.ModuleType("subscription_cli_under_test")
            mod.__file__ = src
            exec(compile(code, src, "exec"), mod.__dict__)
        with mock.patch.dict(os.environ, {**self.SECRETS, **self.KEEP}, clear=True), \
                mock.patch.object(mod, "binary_path", lambda p: "/opt/codex/bin/codex"):
            env = mod._env_for("codex-subscription", "/dev/shm/home1")
        for k in self.SECRETS:
            self.assertNotIn(k, env)
        for k, v in self.KEEP.items():
            if k != "PATH":
                self.assertEqual(env[k], v)
        self.assertTrue(env["PATH"].endswith("/usr/bin"))
        self.assertEqual(env["CODEX_HOME"], "/dev/shm/home1", "the CLI's own credential home")
        self.assertEqual((env["CI"], env["NO_COLOR"], env["TERM"]), ("1", "1", "dumb"))
        # The installer env is built from the same scrubbed copy.
        self.assertNotIn("env = dict(os.environ)", code)


if __name__ == "__main__":
    unittest.main()
