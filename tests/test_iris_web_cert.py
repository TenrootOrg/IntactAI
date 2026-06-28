"""Tests for ensure_iris_web_cert — the IRIS web TLS cert self-heal.

The IRIS web cert is operator-generated + gitignored; only install-time
lib/modules.sh creates it (gated on iris.enabled). So enabling IRIS later, or a
change_ip that removed the cert while IRIS was disabled, leaves intact_iris_nginx
crash-looping on a missing cert. Every IRIS bring-up path now calls this helper
to sync the cert from the shared nginx cert (missing-only, never clobbering a
present one) and generate the Root CA if absent.

Uses real temp dirs; only openssl (run_command) is mocked.

Run:  docker exec intact_backend python /app/workdir/tests/test_iris_web_cert.py
"""

import os
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import iris as I   # noqa: E402


class _Patch:
    def __init__(self, **kw):
        self.kw, self.saved = kw, {}

    def __enter__(self):
        for k, v in self.kw.items():
            self.saved[k] = getattr(I, k)
            setattr(I, k, v)
        return self

    def __exit__(self, *a):
        for k, v in self.saved.items():
            setattr(I, k, v)


def _scratch():
    """Return (root_workdir, iris_work_dir) under a fresh temp tree."""
    root = tempfile.mkdtemp(prefix="iris_cert_test_")
    iris_wd = os.path.join(root, "modules", "iris")
    os.makedirs(iris_wd, exist_ok=True)
    return root, iris_wd


def _write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def _nginx_certs(root, crt="NGINX-CERT", key="NGINX-KEY"):
    _write(os.path.join(root, "modules", "nginx", "ssl", "nginx-cert.crt"), crt)
    _write(os.path.join(root, "modules", "nginx", "ssl", "nginx-cert.key"), key)


def _web(iris_wd, name):
    return os.path.join(iris_wd, "config", "certificates", "web_certificates", name)


def _noop_ca():
    # Pretend openssl ran fine; record calls.
    calls = []
    def fake(cmd, **kw):
        calls.append(cmd)
        return {"success": True, "stdout": "", "error": ""}
    return fake, calls


def test_missing_cert_synced_from_nginx():
    root, iris_wd = _scratch()
    _nginx_certs(root)
    fake, _ = _noop_ca()
    with _Patch(WORKDIR=root, run_command=fake):
        I.ensure_iris_web_cert(iris_wd)
    assert open(_web(iris_wd, "iris_dev_cert.pem")).read() == "NGINX-CERT"
    assert open(_web(iris_wd, "iris_dev_key.pem")).read() == "NGINX-KEY"
    # world-readable so the non-root iris nginx can read the bind-mount
    assert (os.stat(_web(iris_wd, "iris_dev_cert.pem")).st_mode & 0o777) == 0o644


def test_present_cert_not_clobbered():
    root, iris_wd = _scratch()
    _nginx_certs(root)
    _write(_web(iris_wd, "iris_dev_cert.pem"), "OPERATOR-CERT")
    _write(_web(iris_wd, "iris_dev_key.pem"), "OPERATOR-KEY")
    fake, _ = _noop_ca()
    with _Patch(WORKDIR=root, run_command=fake):
        I.ensure_iris_web_cert(iris_wd)
    assert open(_web(iris_wd, "iris_dev_cert.pem")).read() == "OPERATOR-CERT"
    assert open(_web(iris_wd, "iris_dev_key.pem")).read() == "OPERATOR-KEY"


def test_no_nginx_cert_does_not_create_and_does_not_raise():
    root, iris_wd = _scratch()
    # no nginx certs written
    fake, _ = _noop_ca()
    with _Patch(WORKDIR=root, run_command=fake):
        I.ensure_iris_web_cert(iris_wd)   # must not raise
    assert not os.path.exists(_web(iris_wd, "iris_dev_cert.pem"))


def test_root_ca_generated_when_missing():
    root, iris_wd = _scratch()
    _nginx_certs(root)
    fake, calls = _noop_ca()
    with _Patch(WORKDIR=root, run_command=fake):
        I.ensure_iris_web_cert(iris_wd)
    assert any("openssl req -x509" in c and "irisRootCACert.pem" in c for c in calls), \
        "Root CA generation should be attempted when absent"


def test_root_ca_not_regenerated_when_present():
    root, iris_wd = _scratch()
    _nginx_certs(root)
    _write(os.path.join(iris_wd, "config", "certificates", "rootCA", "irisRootCACert.pem"), "CA")
    fake, calls = _noop_ca()
    with _Patch(WORKDIR=root, run_command=fake):
        I.ensure_iris_web_cert(iris_wd)
    assert not any("openssl req -x509" in c for c in calls), \
        "Root CA must not be regenerated when it already exists"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"PASS {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print(f"\n{len(fns)-failed}/{len(fns)} passed")
    sys.exit(1 if failed else 0)
