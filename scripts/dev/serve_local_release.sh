#!/usr/bin/env bash
# DEV-ONLY TOOL. Not shipped, not run by CI, not run by install.sh or upgrade.
#
# Serves a directory of locally-built release assets over HTTP, speaking the
# small subset of the GitHub REST API that lib/upgrade/refs.sh, lib/release.sh
# and scripts/prepare_package.sh actually call. Point INTACT_GH_API_BASE and
# INTACT_GH_DL_BASE at it and every online path runs for real against local
# files.
#
# WHY THIS EXISTS. TenrootOrg/IntactAI is private. A box with no GitHub token
# -- which is the state of this dev box, and of any fresh checkout -- gets 404
# from every releases endpoint, so the online upgrade, `--list`, `--plan` and
# prepare_package.sh cannot be exercised at all. The alternative to this is
# putting a fake `curl` first on PATH, which tests/ already does for unit
# tests; that works for asserting on arguments but not for a real multi-GB
# download through the real resume/digest logic, and it cannot serve the
# helper container at all.
#
# WHAT IT IS NOT: a GitHub emulator. It implements exactly four routes, returns
# the handful of fields the callers read, and ignores authentication entirely
# (any token, or none, is accepted). Anything else 404s loudly rather than
# guessing.
#
# Usage:
#   scripts/dev/serve_local_release.sh <assets_dir> [port] [bind_addr]
#
#   assets_dir  a directory whose subdirectories are release tags:
#                 <assets_dir>/intact-20260811/<tag>.index.json
#                 <assets_dir>/intact-20260811/<tag>-elk.tar
#                 ...
#               A flat directory of assets is also accepted when it contains
#               exactly one tag's files; the tag is then inferred from them.
#
# Then, in another shell:
#   export INTACT_GH_API_BASE=http://<addr>:<port>
#   export INTACT_GH_DL_BASE=http://<addr>:<port>
#   sudo -E bash scripts/upgrade.sh --list
set -euo pipefail

ASSETS_DIR="${1:?usage: serve_local_release.sh <assets_dir> [port] [bind_addr]}"
PORT="${2:-877}"
# 0.0.0.0 by default, deliberately: the upgrade helper runs as a SIBLING
# CONTAINER (services/upgrade_launcher.py), so a server bound to 127.0.0.1
# would be reachable from the host and invisible to the very process that does
# the downloading. Binding all interfaces is safe here because this only ever
# serves release assets that are already on the box.
BIND="${3:-0.0.0.0}"

ASSETS_DIR="$(cd "$ASSETS_DIR" && pwd)"

exec python3 - "$ASSETS_DIR" "$PORT" "$BIND" <<'PY'
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ASSETS_DIR, PORT, BIND = sys.argv[1], int(sys.argv[2]), sys.argv[3]

# Whatever INTACT_REPO the caller uses; the route matcher accepts any owner/name
# rather than hardcoding one, so this serves a renamed fork without edits.
REPO_RE = r"[^/]+/[^/]+"


def discover():
    """{tag: {asset_name: abspath}} from the assets directory.

    Two layouts, because both turn up in practice: one subdirectory per tag
    (what build_local_release_assets.sh writes), or a single flat directory
    someone pointed at directly. In the flat case the tag is read off the
    asset names -- every asset a release publishes is prefixed `<tag>` or
    `intact-upgrade-<tag>`, so it is recoverable without being told.
    """
    releases = {}

    def add(tag, path):
        releases.setdefault(tag, {})[os.path.basename(path)] = path

    def tag_of(name):
        m = re.match(r"^(intact-\d{8}[^.]*)\.(index|manifest)\.json$", name)
        if m:
            return m.group(1)
        m = re.match(r"^(intact-\d{8}[^.]*)-[a-z0-9_]+\.tar(\.gz)?$", name)
        if m:
            return m.group(1)
        m = re.match(r"^intact-upgrade-(intact-\d{8}[^.]*)\.tar", name)
        if m:
            return m.group(1)
        return None

    for entry in sorted(os.listdir(ASSETS_DIR)):
        full = os.path.join(ASSETS_DIR, entry)
        if os.path.isdir(full):
            for f in sorted(os.listdir(full)):
                p = os.path.join(full, f)
                if os.path.isfile(p):
                    add(entry, p)
        elif os.path.isfile(full):
            t = tag_of(entry)
            if t:
                add(t, full)
    return releases


def release_doc(tag, assets, host):
    """The subset of GitHub's release object the callers read.

    `url` and `browser_download_url` are both filled with the same download
    route: refs.sh's upgrade_fetch_manifest_only and prepare_package.sh use
    `url` (with Accept: application/octet-stream, which real GitHub needs and
    this ignores), while other paths build the download URL themselves from
    INTACT_GH_DL_BASE. Serving one route under both names keeps the two in
    step.
    """
    base = "http://%s/%s/releases/download/%s" % (host, os.environ.get(
        "LOCAL_RELEASE_REPO", "TenrootOrg/IntactAI"), tag)
    return {
        "tag_name": tag,
        "name": tag,
        "draft": False,
        "prerelease": False,
        "assets": [
            {
                "name": n,
                "size": os.path.getsize(p),
                "url": "%s/%s" % (base, n),
                "browser_download_url": "%s/%s" % (base, n),
                "content_type": "application/octet-stream",
            }
            for n, p in sorted(assets.items())
        ],
    }


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("[release-server] %s\n" % (fmt % args))

    # ---- helpers -------------------------------------------------------
    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _not_found(self, why):
        self._json({"message": why, "documentation_url": "local-release-server"}, 404)

    def _send_file(self, path):
        """Serve a file, honouring a single Range.

        Range matters: lib/release.sh downloads with `curl -C -`, so an
        interrupted multi-GB asset resumes rather than restarting. A server
        that ignored Range would silently make every resume redownload from
        zero and quietly hide a bug in that logic.
        """
        size = os.path.getsize(path)
        rng = self.headers.get("Range")
        start, end = 0, size - 1
        partial = False
        if rng:
            m = re.match(r"bytes=(\d*)-(\d*)$", rng.strip())
            if m:
                s, e = m.group(1), m.group(2)
                if s:
                    start = int(s)
                    if e:
                        end = int(e)
                elif e:
                    # suffix range: last N bytes
                    start = max(0, size - int(e))
                if start >= size:
                    self.send_response(416)
                    self.send_header("Content-Range", "bytes */%d" % size)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                partial = True

        length = end - start + 1
        self.send_response(206 if partial else 200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        if partial:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.end_headers()
        with open(path, "rb") as fh:
            fh.seek(start)
            remaining = length
            while remaining > 0:
                chunk = fh.read(min(1 << 20, remaining))
                if not chunk:
                    break
                self.wfile.write(chunk)
                remaining -= len(chunk)

    # ---- routes --------------------------------------------------------
    def do_GET(self):
        releases = discover()
        host = self.headers.get("Host") or "%s:%d" % (BIND, PORT)
        path = self.path.split("?", 1)[0]

        m = re.match(r"^/repos/%s/releases/tags/(.+)$" % REPO_RE, path)
        if m:
            tag = m.group(1)
            if tag not in releases:
                return self._not_found("Not Found")
            return self._json(release_doc(tag, releases[tag], host))

        if re.match(r"^/repos/%s/releases/?$" % REPO_RE, path):
            # Newest first, the same order the real API returns and the order
            # refs.sh's table assumes before it sorts by its own date key.
            return self._json([release_doc(t, releases[t], host)
                               for t in sorted(releases, reverse=True)])

        if re.match(r"^/rate_limit$", path):
            # The quota widget calls this directly. Report something plainly
            # synthetic rather than a plausible-looking number.
            return self._json({"resources": {"core": {
                "limit": 999999, "remaining": 999999, "reset": 0, "used": 0}}})

        m = re.match(r"^/%s/releases/download/([^/]+)/(.+)$" % REPO_RE, path)
        if m:
            tag, name = m.group(1), m.group(2)
            p = (releases.get(tag) or {}).get(name)
            if not p:
                return self._not_found("asset %s not in %s" % (name, tag))
            return self._send_file(p)

        return self._not_found("no route for %s" % path)

    def do_HEAD(self):
        # curl -C - probes with HEAD on some paths; answer it rather than 501.
        self.do_GET()


if __name__ == "__main__":
    found = discover()
    sys.stderr.write("[release-server] serving %d release(s) from %s\n"
                     % (len(found), ASSETS_DIR))
    for t in sorted(found):
        total = sum(os.path.getsize(p) for p in found[t].values())
        sys.stderr.write("[release-server]   %s: %d asset(s), %.2f GB\n"
                         % (t, len(found[t]), total / 1e9))
    sys.stderr.write("[release-server] listening on http://%s:%d\n" % (BIND, PORT))
    ThreadingHTTPServer((BIND, PORT), Handler).serve_forever()
PY
