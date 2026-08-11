#!/usr/bin/env python3
"""Rewrite a staged config file back to its shipping defaults.

Called by sanitize-config-yaml.sh with (target-path, src, dst). Lives in its
own file rather than a heredoc inside the hook so it can be unit-tested
directly — see tests/test_config_sanitizer.py. Two regex bugs shipped from the
heredoc version (a `\\s*` that swallowed newlines, and a `.*?` that stopped at
the `#` inside Portainer's `1234qwer!@#$` and mangled the line), both of which
a unit test would have caught in seconds.

Textual edit, NOT a yaml round-trip: both files are full of operator-facing
comments that PyYAML would silently discard, and the whole point of tracking
them is that a human reads them before installing.
"""

import re
import sys
from collections import Counter

DEFAULT_PW = "123123"

# Values that are ALREADY shipping defaults and must be left exactly as-is.
# Portainer's is deliberately >=12 chars because Portainer refuses shorter
# ones; forcing it to 123123 would silently change shipped behaviour
# (install.sh would then generate a random password instead).
SHIPPED = {DEFAULT_PW, "1234qwer!@#$"}

# qa/qa-config.yaml: the leaf keys blanked on commit, per top-level section.
# An allowlist rather than "blank everything" so that adding a non-secret knob
# (a timeout, an output path) does not silently get wiped on the next commit.
QA_SECRET_KEYS = {
    "platform": ("host", "sudo_user", "sudo_password"),
    "windows": ("host", "username", "password"),
}


def _pat(prefix):
    """key: value [# comment], where a QUOTED value may itself contain '#'.

    Matching a quoted value as a single unit is load-bearing: a non-greedy
    `.*?` stops at the '#' inside Portainer's shipped '1234qwer!@#$' and treats
    the remainder as a comment, rewriting the line to a mangled `123123#$'`.

    The trailing group is `[ \\t]*` and not `\\s*` for an equally load-bearing
    reason: `\\s` matches a newline, so it ate the line ending and every edit
    added a blank line to the file.

    The unquoted alternative stops at WHITESPACE, not at '#'. In YAML a '#'
    only opens a comment when something blank precedes it, so `p@ss#word` is
    one value -- but `[^\\s#]*` cut it at the hash, treated `#word` as a
    comment, and wrote back `123123#word`. Same mangling as the quoted case
    above, reached by a different route: `1234qwer!@#$` written WITHOUT quotes
    came out as `123123#$`. The tracked config.yaml happens to quote it, which
    is why this survived unnoticed until tests/test_config_sanitizer.py.
    """
    return (r"^(" + prefix + r":[ \t]*)"
            r"('[^']*'|\"[^\"]*\"|[^\s]*)"
            r"([ \t]*(?:#.*)?)$")


def _value(match):
    """The staged value with quotes and surrounding space stripped."""
    return match.group(2).strip().strip("\"'")


def sanitize_main_config(text):
    """config.yaml -> (sanitized text, list of field names changed)."""
    out, changed = [], []

    for ln in text.splitlines(keepends=True):
        # options.github_token -> always empty. This is the one that matters: a
        # live PAT to a private org, written at runtime, never something to ship.
        m = re.match(_pat(r"\s*github_token"), ln)
        if m and _value(m):
            out.append(f"{m.group(1)}''{m.group(3)}\n")
            changed.append("github_token")
            continue

        # Module passwords -> back to the shipped default. Operators are told to
        # change these at install time; whatever this box uses is not for git.
        m = re.match(_pat("    password"), ln)
        if m and _value(m) not in SHIPPED:
            out.append(f"{m.group(1)}{DEFAULT_PW}{m.group(3)}\n")
            changed.append("password")
            continue

        # A fresh checkout must land in setup mode, or the first install has
        # first_login: false with no stored credential and fails closed = locked out.
        m = re.match(_pat("first_login"), ln)
        if m and _value(m).lower() != "true":
            out.append(f"{m.group(1)}true{m.group(3)}\n")
            changed.append("first_login")
            continue

        out.append(ln)

    return "".join(out), changed


def sanitize_qa_config(text):
    """qa/qa-config.yaml -> (sanitized text, list of field names changed).

    Section-aware: only `host`/`sudo_user`/`sudo_password` under `platform:`
    and `host`/`username`/`password` under `windows:` are blanked. A bare
    key-name match would be wrong the moment someone adds a `password:` under
    a future non-secret section, and would also blank `run.output_dir` if the
    allowlist were ever loosened to "anything that looks like a path".
    """
    out, changed = [], []
    section = None

    for ln in text.splitlines(keepends=True):
        top = re.match(r"^(\w+):", ln)
        if top:
            section = top.group(1)

        keys = QA_SECRET_KEYS.get(section, ())
        hit = False
        for key in keys:
            m = re.match(_pat("  " + key), ln)
            if m and _value(m):
                out.append(f"{m.group(1)}''{m.group(3)}\n")
                changed.append(f"{section}.{key}")
                hit = True
                break
        if hit:
            continue

        out.append(ln)

    return "".join(out), changed


SANITIZERS = {
    "config.yaml": sanitize_main_config,
    "qa/qa-config.yaml": sanitize_qa_config,
}


def main(argv):
    target, src, dst = argv[1], argv[2], argv[3]

    fn = SANITIZERS.get(target)
    if fn is None:
        # Fail closed. Being asked to sanitize a file with no rules means the
        # caller and this table disagree; copying the input through would
        # publish whatever it holds while reporting success.
        sys.stderr.write(f"sanitize_config.py: no rules for '{target}'\n")
        return 2

    with open(src, encoding="utf-8") as fh:
        text = fh.read()

    cleaned, changed = fn(text)

    with open(dst, "w", encoding="utf-8") as fh:
        fh.write(cleaned)

    if changed:
        counts = Counter(changed)
        sys.stderr.write("  sanitized: " + " ".join(
            f"{k}x{v}" if v > 1 else k for k, v in counts.items()) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
