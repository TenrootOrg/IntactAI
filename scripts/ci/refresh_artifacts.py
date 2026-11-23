#!/usr/bin/env python3
"""Every release ships the newest Velociraptor artifacts.

WHY. Since the bundle was baked into the image (0ac3e378, 2026-06-23) nothing
updated it, while DetectRaptor's indicators moved daily. The release build now
runs this just before it bakes the Velociraptor image, over everything the
server's import artifacts would fetch: Server.Import.Extras' list as defined by
this release's own Velociraptor binary (Sigma, Artifact Exchange, Rapid7,
Registry Hunter, SQLiteHunter, Triage) plus DetectRaptor.

It takes the newest version of every artifact, new ones included, UNLESS a gate
says that version would hurt. These run with full privileges on customers'
endpoints, and upstream can simply be wrong: on 2026-11-23 DetectRaptor's
LolDrivers list went from 368 KB to its header line. A held artifact keeps the
copy from git and is named in the build summary:
  - our own fix: KEEP_OURS, or any Custom./tenRoot./IRIS. artifact
  - it fails `velociraptor artifacts verify` (and the copy we have does not)
  - an indicator list lost more than 30%
  - it gained a way to execute, write or send that it did not have, or a tool
    from a new host
  - Case Analysis reads this artifact and a column it outputs is gone
  - a new artifact would shadow one built into the binary

If a source cannot be fetched the build FAILS: a release that quietly ships old
artifacts is what this exists to prevent, and re-running is cheap.
"""
import argparse
import ast
import base64
import csv
import gzip
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

import yaml

DETECTRAPTOR = "mgreen27/DetectRaptor"
BUNDLE = "modules/velociraptor/bundled_artifacts"
MAPPER = "modules/backend/services/fusion/mappers/agentic.py"
MIN_KEEP = 0.7                       # a list may not lose more than 30% in one refresh
MAX_FILE = 8 * 1024 * 1024
MAX_ARCHIVE_TOTAL = 400 * 1024 * 1024

# Upstream artifacts we deliberately changed; upstream's copy would undo the fix.
KEEP_OURS = {
    "Windows.Applications.Disk2VHD",                   # ec89164d: no internal share path
    "Server.Monitoring.ScheduleDeleteMonitoringData",  # our retention defaults
}
OUR_PREFIXES = ("Custom.", "tenRoot.", "IRIS.")

_NAME = re.compile(r"^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$")
_BLOB = re.compile(r'(base64decode\(string=")([A-Za-z0-9+/=]+)(")')
_POWER = re.compile(r"\b(execve|http_client|upload|upload_directory|rm|copy|write_csv|write_jsonl|"
                    r"mail|splunk_upload|elastic_upload|s3_upload|gcs_upload|azure_upload|sftp_upload)\s*\(")
_SLACK = re.compile(rb"(?:Slack)?https://hooks\.slack\.com/services/[^\s'\"]+")
_NOT_A_COLUMN = {"SELECT", "FROM", "WHERE", "GROUP", "BY", "ORDER", "LIMIT", "AS", "AND", "OR", "NOT",
                 "LET", "TRUE", "FALSE", "NULL", "IF", "DESC"}


class SourceFailed(RuntimeError):
    pass


# ---- gates (pure) ----------------------------------------------------------------

def _is_list(p):
    kind = p.get("type")
    if kind in ("csv", "yara"):
        return True
    default = p.get("default")           # upstream also keeps CSV lists in hidden parameters
    return kind == "hidden" and isinstance(default, str) and "\n" in default \
        and "," in default.split("\n", 1)[0]


def list_sizes(doc):
    out = {}
    for p in doc.get("parameters") or []:
        if _is_list(p):
            out[p["name"]] = len(str(p.get("default") or ""))
    for i, s in enumerate(doc.get("sources") or []):
        for j, m in enumerate(_BLOB.finditer(str(s.get("query") or ""))):
            out[f"rule pack {i}.{j}"] = len(m.group(2))
    return out


def _vql(doc):
    parts = [str(doc.get("precondition") or "")]
    for s in doc.get("sources") or []:
        parts += [str(s.get("query") or ""), str(s.get("precondition") or "")]
    for e in doc.get("export"), doc.get("imports"):
        parts.append(str(e or ""))
    return _BLOB.sub(r"\1\3", "\n".join(parts))


def _tool_hosts(doc):
    out = set()
    for t in doc.get("tools") or []:
        if isinstance(t, dict):
            out.add((t.get("name"), urllib.parse.urlparse(str(t.get("url") or "")).netloc))
    return out


def output_columns(doc):
    """The names a query selects or aliases, for artifacts Case Analysis reads."""
    q = _vql(doc)
    words = set(re.findall(r"\bas\s+([A-Za-z_]\w*)", q, re.I))
    for block in re.findall(r"\bSELECT\b(.*?)\bFROM\b", q, re.I | re.S):
        words |= set(re.findall(r"\b([A-Z]\w*)\b(?!\s*[(=])", block))
    return {w for w in words if w.upper() not in _NOT_A_COLUMN}


def gate(name, old, new, mapped=False, builtin=False):
    """(outcome, why): same | new | updated | ours | held."""
    if name in KEEP_OURS or name.startswith(OUR_PREFIXES):
        return ("same", "") if old == new else ("ours", "our own version is kept")
    if old is None:
        return ("held", "would shadow an artifact built into Velociraptor") if builtin else ("new", "")
    if old == new:
        return "same", ""
    before, after = list_sizes(old), list_sizes(new)
    for k, was in before.items():
        if was >= 1000 and after.get(k, was) < was * MIN_KEEP:
            return "held", f"{k} shrank from {was:,} to {after[k]:,} characters"
    gained = set(_POWER.findall(_vql(new))) - set(_POWER.findall(_vql(old)))
    if gained:
        return "held", "gained " + ", ".join(sorted(gained))
    hosts = {h for _, h in _tool_hosts(old)}
    fresh = sorted(f"{n} ({h})" for n, h in _tool_hosts(new) if h and h not in hosts)
    if fresh:
        return "held", "tool from a new host: " + ", ".join(fresh)
    if mapped:
        text = set(re.findall(r"\w+", _vql(new)))
        gone = sorted(output_columns(old) - text)
        if gone:
            return "held", "Case Analysis reads it and these columns are gone: " + ", ".join(gone[:6])
    return "updated", ""


def file_name(name):
    return name.replace(".", "__") + ".yaml"


# ---- fetching --------------------------------------------------------------------

def _get(url, accept=None):
    req = urllib.request.Request(url, headers={"User-Agent": "intact-ci"})
    if accept:
        req.add_header("Accept", accept)
    token = os.environ.get("GITHUB_TOKEN")
    if token and urllib.parse.urlparse(url).netloc == "api.github.com":
        req.add_header("Authorization", f"Bearer {token}")
    last = None
    for _ in range(3):
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            last = e
            if e.code < 500:
                break
        except OSError as e:
            last = e
    raise SourceFailed(f"{url}: {last}")


def _parse(raw):
    """(scrubbed bytes, doc) for a usable artifact definition, else None. Nothing from
    an archive is written to a path it chose: the file name comes from a checked name."""
    raw = _SLACK.sub(b"https://hooks.slack.com/services/XXXX/YYYY/ZZZZ", raw)
    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError:
        return None
    if isinstance(doc, dict) and isinstance(doc.get("name"), str) and _NAME.match(doc["name"]):
        return raw, doc
    return None


def read_zip(data):
    out, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for i in z.infolist():
            if i.is_dir() or not i.filename.lower().endswith((".yaml", ".yml")) or i.file_size > MAX_FILE:
                continue
            total += i.file_size
            if total > MAX_ARCHIVE_TOTAL:
                raise SourceFailed("archive is implausibly large")
            got = _parse(z.read(i))
            if got:
                out[got[1]["name"]] = got
    return out


def read_detectraptor(ref):
    sha = _get(f"https://api.github.com/repos/{DETECTRAPTOR}/commits/{ref}",
               "application/vnd.github.sha").decode().strip()
    out = {}
    data = _get(f"https://api.github.com/repos/{DETECTRAPTOR}/tarball/{sha}")
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            parts = m.name.split("/")
            if m.isreg() and len(parts) == 3 and parts[1] == "vql" and parts[2].endswith(".yaml") \
                    and m.size <= MAX_FILE:
                got = _parse(tf.extractfile(m).read())
                if got and got[1]["name"].startswith("DetectRaptor."):
                    out[got[1]["name"]] = got
    return sha, out


def _velo(verifier, *args, timeout=120):
    return subprocess.run([verifier, "--nobanner", *args], capture_output=True, text=True, timeout=timeout)


def extras_sources(verifier):
    """[(name, url)] from Server.Import.Extras in THIS release's binary, so a source
    Velociraptor adds is picked up with no change here."""
    r = _velo(verifier, "artifacts", "show", "Server.Import.Extras")
    doc = yaml.safe_load(r.stdout) if r.returncode == 0 else None
    details = next((p.get("default") for p in (doc or {}).get("parameters") or [] if p.get("name") == "Details"), None)
    rows = list(csv.DictReader(io.StringIO(details or "")))
    if not rows:
        raise SourceFailed("Server.Import.Extras has no source list")
    return [(x["Name"], x["URL"]) for x in rows]


def fetch_all(verifier, ref):
    """({artifact: (raw, doc)}, [(source, detail, count)]). Same order as the imports."""
    merged, provenance = {}, []
    for label, url in extras_sources(verifier):
        got = read_zip(_get(url))
        if not got:
            raise SourceFailed(f"{label}: no artifacts in {url}")
        merged.update(got)
        provenance.append((label, url, len(got)))
    sha, got = read_detectraptor(ref)
    if not got:
        raise SourceFailed("DetectRaptor: no artifacts")
    merged.update(got)
    provenance.append(("DetectRaptor", sha[:12], len(got)))
    return merged, provenance


def builtin_names(verifier):
    r = _velo(verifier, "query", "--format=jsonl", "SELECT name FROM artifact_definitions() WHERE built_in")
    names = {json.loads(l)["name"] for l in r.stdout.splitlines() if l.startswith("{")}
    if not names:
        raise SourceFailed("could not list the binary's built-in artifacts")
    return names


def mapped_artifacts(mapper):
    with open(mapper, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    for n in tree.body:
        if isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "SUPPORTED_ARTIFACTS":
            return {x.value.lower() for x in ast.walk(n.value)
                    if isinstance(x, ast.Constant) and isinstance(x.value, str)}
    raise SourceFailed("SUPPORTED_ARTIFACTS not found")


# ---- verifying and applying ------------------------------------------------------

def _verifiable(raw):
    # The verifier's parser refuses string literals past roughly 100 KB, though the
    # same artifacts load and run (checked on 0.77.3): verify the logic, not the pack.
    short = base64.b64encode(b"x").decode()
    return _BLOB.sub(lambda m: m.group(1) + short + m.group(3), raw.decode("utf-8", "replace")).encode()


def verify(verifier, raw, tmp, definitions):
    """(passed, first problem)."""
    path = os.path.join(tmp, "candidate.yaml")
    with open(path, "wb") as fh:
        fh.write(_verifiable(raw))
    try:
        r = _velo(verifier, "--definitions", definitions, "artifacts", "verify", "--issues_only",
                  "--max_length=4000000", path)
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, f"verifier did not run: {e}"
    text = (r.stdout + r.stderr).strip()
    if r.returncode != 0 or "[ERROR]" in text:
        lines = [l for l in text.splitlines() if "ERROR" in l] or text.splitlines() or [f"exit {r.returncode}"]
        return False, re.sub(r"^\S+\s+\S+\s+", "", lines[0])[:150]
    return True, ""


def read_bundle(bundle):
    out = {}
    for f in sorted(os.listdir(bundle)):
        if f.endswith(".yaml"):
            path = os.path.join(bundle, f)
            with open(path, "rb") as fh:
                got = _parse(fh.read())
            if got:
                out[got[1]["name"]] = (path, got[0], got[1])
    return out


def refresh(bundle, upstream, verifier, builtin, mapped, dry_run=False):
    """{name: (outcome, why)}; writes what passed every gate."""
    have = read_bundle(bundle)
    results, todo = {}, {}
    for name, (raw, doc) in sorted(upstream.items()):
        old = have[name][2] if name in have else None
        kind, why = gate(name, old, doc, mapped=name.lower() in mapped, builtin=name in builtin)
        results[name] = (kind, why)
        if kind in ("updated", "new"):
            todo[name] = raw
    with tempfile.TemporaryDirectory() as tmp:
        # Candidates are verified against the bundle as it will be, so one that
        # calls another new artifact resolves.
        staged = os.path.join(tmp, "staged")
        shutil.copytree(bundle, staged)
        for name, raw in todo.items():
            with open(os.path.join(staged, os.path.basename(have[name][0]) if name in have else file_name(name)), "wb") as fh:
                fh.write(_verifiable(raw))
        for f in os.listdir(staged):             # the loader needs no rule packs either
            p = os.path.join(staged, f)
            with open(p, "rb") as fh:
                body = fh.read()
            with open(p, "wb") as fh:
                fh.write(_verifiable(body))
        for name, raw in todo.items():
            ok, problem = verify(verifier, raw, tmp, staged)
            if not ok and name in have and not verify(verifier, have[name][1], tmp, staged)[0]:
                ok = True                        # no worse than the copy we already ship
            if not ok:
                results[name] = ("held", "verifier: " + problem)
                continue
            if not dry_run:
                path = have[name][0] if name in have else os.path.join(bundle, file_name(name))
                with open(path, "wb") as fh:
                    fh.write(raw)
    return results


def report(provenance, results, dry_run=False):
    lines = ["### Velociraptor artifacts" + (" (dry run)" if dry_run else ""), "",
             "| Source | Version | Artifacts |", "|---|---|---|"]
    lines += [f"| {a} | `{b}` | {c} |" for a, b, c in provenance]
    lines.append("")
    for key, title in (("updated", "Updated"), ("new", "New"), ("same", "Already newest"),
                       ("ours", "Our own version kept"), ("held", "HELD BACK")):
        rows = [(n, w) for n, (k, w) in results.items() if k == key]
        if not rows:
            continue
        lines.append(f"**{title}: {len(rows)}**")
        if key == "held" or key == "ours":
            lines += [f"- `{n}`: {w}" for n, w in rows]
        lines.append("")
    return "\n".join(lines)


def fetch_verifier(version, dest):
    """This release's own Velociraptor binary: the same parser the server will run."""
    v = version.lstrip("v")
    tags = [f"v{v}", "v" + ".".join(v.split(".")[:2])]
    name = f"velociraptor-v{v}-linux-amd64-musl"
    for tag in tags:
        for suffix in (".gz", ""):
            try:
                data = _get(f"https://github.com/Velocidex/velociraptor/releases/download/{tag}/{name}{suffix}")
            except SourceFailed:
                continue
            with open(dest, "wb") as fh:
                fh.write(gzip.decompress(data) if suffix else data)
            os.chmod(dest, 0o755)
            return dest
    raise SourceFailed(f"Velociraptor {v} binary not found")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--bundle", default=BUNDLE)
    ap.add_argument("--mapper", default=MAPPER)
    ap.add_argument("--config", default="config.yaml", help="for versions.velociraptor")
    ap.add_argument("--verifier", help="velociraptor binary (default: download this release's)")
    ap.add_argument("--detectraptor-ref", default="master")
    ap.add_argument("--dry-run", action="store_true", help="report only, write nothing")
    ap.add_argument("--summary", help="append the report to this file (GITHUB_STEP_SUMMARY)")
    args = ap.parse_args()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            verifier = args.verifier
            if not verifier:
                with open(args.config, encoding="utf-8") as fh:
                    version = yaml.safe_load(fh)["versions"]["velociraptor"]
                verifier = fetch_verifier(str(version), os.path.join(tmp, "velociraptor"))
            upstream, provenance = fetch_all(verifier, args.detectraptor_ref)
            results = refresh(args.bundle, upstream, verifier, builtin_names(verifier),
                              mapped_artifacts(args.mapper), args.dry_run)
    except (SourceFailed, OSError, KeyError, ValueError, zipfile.BadZipFile, tarfile.TarError) as e:
        print(f"::error::Artifacts could not be refreshed, so this release would ship old ones: {e}", flush=True)
        return 1
    text = report(provenance, results, args.dry_run)
    print(text, flush=True)
    if args.summary:
        with open(args.summary, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    held = [n for n, (k, _) in results.items() if k == "held"]
    if held:
        print(f"::warning::{len(held)} artifact(s) held back: " + ", ".join(held[:12]), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
