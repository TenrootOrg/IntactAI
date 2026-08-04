"""RUN the copyable Prepare scripts. Do not merely read them.

tests/test_prepare_manual_script.py greps the generated text -- that the bash
mentions sha256sum, that the PowerShell sorts its parts. Every one of those
assertions passed while the scripts had four bugs that made them fail on a real
Windows box: a placeholder tag that died as "Illegal characters in path", a
`throw "$env:GITHUB_TOKEN"` that interpolated the variable into its own error
and printed "set  first", a paste that ran line-by-line and cascaded, and an
unhandled 401 surfacing as "cannot call a method on a null-valued expression".
`node --check` and `bash -n` passed the whole time too.

Nothing that only READS a script can catch that. So this file executes the
bash one end to end against a fixture that behaves like the GitHub releases
API, and asserts the reassembled file's sha256 matches.

The fixture reproduces the three things that are easy to get wrong and
impossible to notice in a static read:

  * assets are served from the API `url`, and return JSON metadata unless the
    caller sends `Accept: application/octet-stream` -- so a script using
    browser_download_url silently downloads a JSON blob and "succeeds";
  * the package is SPLIT into parts, so reassembly and sort order are
    exercised rather than assumed;
  * anonymous requests work (the releases are public), while a PRESENT but
    empty Authorization header is rejected -- which is what an unconditional
    `Bearer $TOKEN` sends when no token is set.

PowerShell is not executed here: pwsh is not in the backend image and pulling
it would make the suite depend on a network fetch. Its logic is the same shape
and it is covered by the static file plus manual runs in a real pwsh
container; that asymmetry is a known gap, recorded rather than hidden.

Run: docker exec intact_backend python /app/workdir/tests/test_prepare_scripts_actually_run.py
"""

import hashlib
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
STORE = os.path.join(REPO, "modules", "nginx", "html", "js", "stores", "settings.js")
TAG = "intact-20260726"


# ---------------------------------------------------------------------------
# Extract the emitted bash without a JS engine.
#
# The generator is a list of single-quoted JS strings joined by \n. Parsing it
# in Python keeps this test runnable in the backend image, which has no node --
# and a test that cannot run in CI is a test that does not run.
# ---------------------------------------------------------------------------

def _generated_bash(tag=TAG):
    src = open(STORE).read()
    body = src[src.index("prepareManualScript() {"):]
    body = body[:body.index("\n        },")]
    body = body[body.index("return ["):]
    # The tag line is CONCATENATED, not literal:
    #     '  TAG=' + tag + '        # <-- CHANGE to the release you want',
    # A plain single-quoted-string regex skips it entirely, which left TAG
    # unbound and every run failing on line 9 for a reason that had nothing to
    # do with the script. Splice the value in first so the line becomes one
    # ordinary string.
    body = body.replace("' + tag + '", tag)
    lines = []
    for m in re.finditer(r"^\s*'((?:[^'\\]|\\.)*)',?\s*$", body, re.M):
        lines.append(m.group(1)
                     .replace("\\'", "'").replace('\\\\', '\\').replace("\\n", "\n"))
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fixture that behaves like the real releases API
# ---------------------------------------------------------------------------

class _Fixture:
    def __init__(self, part_sizes=(700_000, 700_000, 213_000)):
        self.dir = tempfile.mkdtemp(prefix="pkgfx-")
        self.assets = os.path.join(self.dir, "assets")
        os.makedirs(self.assets)
        whole = os.urandom(sum(part_sizes))
        self.sha = hashlib.sha256(whole).hexdigest()
        base = f"intact-upgrade-{TAG}.tar.gz"
        off = 0
        for i, n in enumerate(part_sizes):
            with open(os.path.join(self.assets, f"{base}.part-{i:02d}"), "wb") as f:
                f.write(whole[off:off + n])
            off += n
        with open(os.path.join(self.assets, f"{base}.sha256"), "w") as f:
            f.write(f"{self.sha}  {base}\n")
        self.port = self._free_port()
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._serve()

    @staticmethod
    def _free_port():
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    def _serve(self):
        root, base_url = self.assets, self.base_url

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj, code=200):
                b = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(b)))
                self.end_headers()
                self.wfile.write(b)

            def do_GET(self):
                auth = self.headers.get("Authorization")
                # Anonymous is fine (public releases). A present-but-empty
                # Bearer is rejected, exactly as GitHub does -- which is what an
                # unconditional `Bearer $TOKEN` sends with no token set.
                if auth is not None and auth.strip() in ("Bearer", "Bearer "):
                    self.send_response(401)
                    self.end_headers()
                    return
                if "/releases/tags/" in self.path:
                    return self._json({"assets": [
                        {"name": n, "size": os.path.getsize(os.path.join(root, n)),
                         "url": f"{base_url}/assets/{n}",
                         "browser_download_url": f"{base_url}/WRONG/{n}"}
                        for n in sorted(os.listdir(root))]})
                if self.path.startswith("/assets/"):
                    if "octet-stream" not in (self.headers.get("Accept") or ""):
                        return self._json({"message": "metadata, not bytes"})
                    p = os.path.join(root, os.path.basename(self.path))
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(os.path.getsize(p)))
                    self.end_headers()
                    with open(p, "rb") as f:
                        shutil.copyfileobj(f, self.wfile)
                    return
                self.send_response(404)
                self.end_headers()

        self.httpd = http.server.HTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        try:
            self.httpd.shutdown()
        except Exception:
            pass
        shutil.rmtree(self.dir, ignore_errors=True)


def _run_bash(env=None):
    """Run the generated bash against the fixture; return (rc, out, workdir, sha)."""
    fx = _Fixture()
    work = tempfile.mkdtemp(prefix="pkgrun-")
    try:
        script = _generated_bash().replace("API=https://api.github.com",
                                           f"API={fx.base_url}")
        e = dict(os.environ)
        e.pop("GITHUB_TOKEN", None)
        e.update(env or {})
        p = subprocess.run(["bash", "-c", script], cwd=work, env=e,
                           capture_output=True, text=True, timeout=120)
        out = os.path.join(work, f"intact-upgrade-{TAG}.tar.gz")
        got = ""
        if os.path.isfile(out):
            h = hashlib.sha256()
            with open(out, "rb") as f:
                for c in iter(lambda: f.read(1 << 20), b""):
                    h.update(c)
            got = h.hexdigest()
        return p.returncode, (p.stdout + p.stderr), work, got, fx.sha
    finally:
        fx.stop()
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------

def test_bash_reproduces_the_published_hash_anonymously():
    """The whole point: run it, and check the bytes."""
    rc, out, _work, got, want = _run_bash()
    assert rc == 0, f"script failed (rc={rc}):\n{out[-800:]}"
    assert got == want, f"hash mismatch\n  want {want}\n  got  {got}\n{out[-400:]}"


def test_bash_reproduces_the_hash_with_a_token_too():
    """A token is optional, and supplying one must not change the outcome."""
    rc, out, _w, got, want = _run_bash({"GITHUB_TOKEN": "fake-token"})
    assert rc == 0, f"script failed with a token (rc={rc}):\n{out[-800:]}"
    assert got == want, f"hash mismatch with a token\n  want {want}\n  got {got}"


def test_bash_joins_split_parts_in_order():
    """The fixture ships three UNEQUAL parts. Joined in any other order the
    bytes still form a file of the right length -- only the hash catches it,
    which is why the hash is the assertion."""
    rc, out, _w, got, want = _run_bash()
    assert rc == 0 and got == want
    assert "joining parts" in out, "the split path was never exercised"


def test_bash_leaves_no_temp_files_behind():
    """A paste should leave only what it meant to download."""
    fx = _Fixture()
    work = tempfile.mkdtemp(prefix="pkgrun-")
    try:
        script = _generated_bash().replace("API=https://api.github.com",
                                           f"API={fx.base_url}")
        e = dict(os.environ)
        e.pop("GITHUB_TOKEN", None)
        subprocess.run(["bash", "-c", script], cwd=work, env=e,
                       capture_output=True, text=True, timeout=120)
        left = sorted(os.listdir(work))
        assert "assets.txt" not in left, f"spilled a temp file: {left}"
        assert not any(n.endswith(".part-00") for n in left), (
            f"left the split parts behind: {left}")
    finally:
        fx.stop()
        shutil.rmtree(work, ignore_errors=True)


def test_bash_fails_cleanly_when_the_api_is_unreachable():
    """And, critically, does NOT take the calling shell down with it -- the
    subshell is what makes this safe to paste."""
    script = _generated_bash().replace("API=https://api.github.com",
                                       "API=http://127.0.0.1:1")
    work = tempfile.mkdtemp(prefix="pkgrun-")
    try:
        e = dict(os.environ)
        e.pop("GITHUB_TOKEN", None)
        # `; echo ALIVE` only prints if the failure stayed inside the subshell.
        p = subprocess.run(["bash", "-c", script + "\necho ALIVE"], cwd=work,
                           env=e, capture_output=True, text=True, timeout=60)
        assert "ALIVE" in p.stdout, (
            "the failure escaped the subshell — pasted into a terminal this "
            "would abort the operator's session")
        assert "Cannot read release" in (p.stdout + p.stderr)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_the_extractor_still_finds_the_generator():
    """If the generator is renamed or restructured, every test above would
    silently stop testing anything. Fail loudly instead."""
    b = _generated_bash()
    assert "curl" in b and "sha256sum" in b and len(b.splitlines()) > 25, (
        "could not extract the bash from settings.js — the tests above are "
        "running against nothing")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
