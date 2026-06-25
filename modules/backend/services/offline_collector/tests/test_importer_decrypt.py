"""Importer container-detection / decrypt-gate tests.

`_decrypt_container_if_needed` decides whether an uploaded collection is plaintext,
password-encrypted (symmetric: a lone 'data.zip'), or X509-encrypted (asymmetric:
'data.zip' + 'metadata.json'), and routes each correctly:
- plaintext            -> passthrough, "UNENCRYPTED" log
- X509, no password    -> passthrough (the server auto-decrypts with its CA key)
- password, no password -> passthrough + an explicit "will fail" warning
- encrypted + password -> decrypt with `velociraptor unzip` (failure raises ValueError)

We can build the container shapes deterministically with zipfile; the only thing we
can't unit-test is a *successful* password decrypt (needs a real encrypted blob +
the velociraptor binary — that's covered by the live E2E).

Run:  docker exec intact_backend python /app/services/offline_collector/tests/test_importer_decrypt.py
"""

import os
import sys
import tempfile
import zipfile
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.offline_collector.importer import _decrypt_container_if_needed   # noqa: E402


def _mkzip(entries):
    """Create a temp zip whose top level contains `entries` (name -> bytes).
    Returns the path (caller-managed temp dir keeps it alive)."""
    d = tempfile.mkdtemp(prefix="imptest_")
    p = os.path.join(d, "upload.zip")
    with zipfile.ZipFile(p, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return p


def _collector():
    logs = []
    return logs, (lambda m, lvl="info": logs.append((lvl, m)))


def test_plaintext_container_passes_through():
    z = _mkzip({"collection_context.json": b"{}", "results/X.json": b"[]"})
    logs, log = _collector()
    assert _decrypt_container_if_needed(z, None, log) == z
    assert any("UNENCRYPTED" in m for _l, m in logs)


def test_x509_container_no_password_passes_through_for_server_decrypt():
    # data.zip + metadata.json == X509 (asymmetric, server auto-decrypts).
    z = _mkzip({"data.zip": b"PK\x03\x04enc", "metadata.json": b'{"Scheme":"x509"}'})
    logs, log = _collector()
    assert _decrypt_container_if_needed(z, None, log) == z
    joined = " ".join(m for _l, m in logs)
    assert "ENCRYPTED" in joined and "X509" in joined
    assert "scheme: x509" in joined


def test_password_container_without_password_warns_and_passes_through():
    # data.zip only (no metadata) == password (symmetric).
    z = _mkzip({"data.zip": b"PK\x03\x04enc"})
    logs, log = _collector()
    assert _decrypt_container_if_needed(z, None, log) == z
    assert any(lvl == "warning" and "password" in m.lower() for lvl, m in logs)
    assert any("scheme: password" in m for _l, m in logs)


def test_non_zip_upload_passes_through():
    d = tempfile.mkdtemp(prefix="imptest_")
    p = os.path.join(d, "notazip.bin")
    with open(p, "wb") as fh:
        fh.write(b"this is not a zip file")
    logs, log = _collector()
    assert _decrypt_container_if_needed(p, "pw", log) == p


def test_encrypted_with_password_but_bogus_blob_raises():
    # A password is supplied and the shape is encrypted, but 'data.zip' is garbage,
    # so `velociraptor unzip --password` recovers nothing -> ValueError (clear error).
    z = _mkzip({"data.zip": b"not-a-real-encrypted-container"})
    logs, log = _collector()
    raised = False
    try:
        _decrypt_container_if_needed(z, "whatever", log)
    except ValueError as e:
        raised = True
        assert "Decryption failed" in str(e)
    assert raised, "expected ValueError on undecryptable container"
    assert any(lvl == "error" for lvl, _m in logs)


def test_scheme_detection_prefers_context_over_data_zip():
    # If somehow both are present, a readable collection_context.json wins (plaintext).
    z = _mkzip({"collection_context.json": b"{}", "data.zip": b"x"})
    logs, log = _collector()
    assert _decrypt_container_if_needed(z, None, log) == z
    assert any("UNENCRYPTED" in m for _l, m in logs)


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
