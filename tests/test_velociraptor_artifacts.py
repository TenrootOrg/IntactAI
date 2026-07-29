"""Two silent-failure modes around the Velociraptor image, both observed live.

1. VQL COMMENT SYNTAX. VQL comments are `--` or `//`; `#` is not a comment,
   it is an invalid token. Two of our own artifacts carried `#`-style
   explanatory comments inside their query blocks, so the server refused to
   compile them on every single boot:

     [ERROR] While compiling artifact tenRoot.IRIS.Timeline.Add: ...
             invalid token '#'

   Nothing surfaced that to an operator -- the containers came up healthy, the
   GUI worked, and the two artifacts simply did not exist. `#` is a comment in
   YAML, in Python and in shell, so it reads as correct to almost everyone.

2. IMAGE TAG vs BINARY VERSION. The Dockerfile COPYs a pre-staged binary and
   tags the image from VELOCIRAPTOR_VERSION. Nothing tied them together, so
   bumping the pin without re-staging produced a mislabelled image. Observed:
   a box running `velociraptor-server:0.76.1` whose binary reported 0.77.1 --
   config, image tag, version table and release manifest all agreed with each
   other and all disagreed with reality.

Both are checked statically here (no container, no network) so CI catches them
before they ship. The authoritative check for #1 is
`velociraptor artifacts verify`, which needs the binary; this is the cheap
approximation that runs everywhere.

Run: docker exec intact_backend python3 /app/workdir/tests/test_velociraptor_artifacts.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
VELO = os.path.join(REPO, "modules", "velociraptor")
BUNDLED = os.path.join(VELO, "bundled_artifacts")
DOCKERFILE = os.path.join(VELO, "Dockerfile")


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        return handle.read()


def _artifact_files():
    out = []
    for root, _dirs, files in os.walk(VELO):
        for name in sorted(files):
            if name.endswith((".yaml", ".yml")):
                out.append(os.path.join(root, name))
    return out


def _query_block_comment_lines(text):
    """Line numbers of `#` comments that sit INSIDE a VQL query block.

    Two kinds of `#` are legitimate and must NOT be reported:

      * `#` in the artifact's `description:` markdown -- these files are full
        of `#### Notes:` headings. Handled by tracking indentation: a
        `query: |` block owns every line indented further than the key, which
        is exactly YAML's own rule.
      * `#` inside a VQL triple-quoted string. Artifacts routinely embed
        PowerShell that way (Windows.Sys.BitLocker does), and in PowerShell
        `#` IS the comment character. Reporting those would push someone to
        "fix" correct code into broken code.
    """
    hits = []
    in_query = False
    in_string = False
    in_block_comment = False
    key_col = 0
    for n, line in enumerate(text.splitlines(), start=1):
        stripped = line.lstrip()
        indent = len(line) - len(stripped)

        # Anchor on the KEY's column, not the line's indent. For `  - query: |`
        # the dash sits at 2 but the key at 4, and the block's content is
        # indented past 4. Using the dash's column instead kept the block
        # "open" across a sibling key at column 4 -- which is how a `notebook:`
        # template several keys later got scanned as if it were the query.
        # `query:` and `precondition:` only. A notebook/suggestion `template:`
        # is markdown or VQL depending on a sibling `type:` field, so scanning
        # them flags legitimate markdown headings (`## 19,20,21: WMI Eventing`)
        # as stray tokens. A check that cries wolf gets deleted, and both real
        # offenders lived in `query:` blocks -- which is the whole bug class.
        key = re.match(r'^(-\s+)?(query|precondition):\s*[|>]', stripped)
        if key:
            in_query, in_string, in_block_comment = True, False, False
            key_col = indent + len(key.group(1) or "")
            continue

        if not in_query:
            continue

        if stripped and indent <= key_col:
            in_query = in_string = in_block_comment = False
            continue

        # VQL /* ... */ block comment: a # inside one is already commented out.
        if in_block_comment:
            if "*/" in line:
                in_block_comment = False
            continue

        # A ''' ... ''' literal can open and close on the same line, so count
        # delimiters rather than treating it as a simple flag.
        delimiters = line.count("'''")
        if in_string:
            if delimiters:
                in_string = (delimiters % 2 == 0)
            continue                               # everything here is data

        if stripped.startswith("#"):
            hits.append(n)

        if delimiters % 2 == 1:
            in_string = True
        elif "/*" in line and "*/" not in line:
            in_block_comment = True
    return hits


# --- 1. VQL comment syntax ---------------------------------------------------


def test_no_artifact_uses_a_hash_comment_inside_a_query():
    offenders = {}
    for path in _artifact_files():
        lines = _query_block_comment_lines(_read(path))
        if lines:
            offenders[os.path.relpath(path, REPO)] = lines

    assert not offenders, (
        "VQL has no `#` comment -- it is an invalid token and the server "
        "refuses to compile the whole artifact, silently:\n" +
        "\n".join(f"  {p}: line(s) {ls}" for p, ls in sorted(offenders.items())) +
        "\nUse `--` instead.")


def test_the_detector_actually_distinguishes_markdown_from_vql():
    """Guards the guard. If this classifier silently matched nothing, the test
    above would pass forever regardless of what shipped."""
    markdown_only = (
        "name: X\n"
        "description: |\n"
        "  #### Notes:\n"
        "  # this is prose, not code\n"
        "sources:\n"
        "  - query: |\n"
        "      SELECT * FROM info()\n")
    assert _query_block_comment_lines(markdown_only) == [], \
        "a # in description markdown must NOT be reported"

    bad_vql = (
        "sources:\n"
        "  - query: |\n"
        "      LET x = if(\n"
        "        # explanatory comment in VQL -- invalid\n"
        "        condition=1, then=2)\n")
    assert _query_block_comment_lines(bad_vql) == [4], \
        "a # inside a query block must be reported"

    # ...and it must stop at the end of the block, not run to EOF.
    trailing = (
        "sources:\n"
        "  - query: |\n"
        "      SELECT * FROM info()\n"
        "parameters:\n"
        "  # this is YAML again, fine\n"
        "  - name: Y\n")
    assert _query_block_comment_lines(trailing) == [], \
        "the detector ran past the end of the query block"

    # An embedded PowerShell/bash payload in a VQL ''' literal: `#` is the
    # comment character in those languages and is entirely correct there.
    # Windows.Sys.BitLocker does exactly this; reporting it would push
    # someone to "fix" working code into broken code.
    embedded = (
        "sources:\n"
        "  - query: |\n"
        "      LET Script = '''$x = 1\n"
        "      # a PowerShell comment, legitimate\n"
        "      Write-Output $x\n"
        "      '''\n"
        "      SELECT * FROM execve(argv=Script)\n")
    assert _query_block_comment_lines(embedded) == [], \
        "a # inside a VQL ''' string is not a VQL comment"

    # ...but VQL after the literal closes is in scope again.
    after_literal = (
        "sources:\n"
        "  - query: |\n"
        "      LET Script = '''$x = 1\n"
        "      # fine, inside the string\n"
        "      '''\n"
        "      # NOT fine, this is VQL again\n"
        "      SELECT * FROM scope()\n")
    assert _query_block_comment_lines(after_literal) == [6], \
        "the string-literal skip must end when the literal closes"

    # A # inside a VQL /* */ block comment is already commented out.
    block_comment = (
        "sources:\n"
        "  - query: |\n"
        "      /*\n"
        "      ## a markdown heading inside a VQL block comment\n"
        "      */\n"
        "      SELECT * FROM scope()\n")
    assert _query_block_comment_lines(block_comment) == [], \
        "a # inside a /* */ VQL comment is not a stray token"

    # A sibling key at the same column as `query` ENDS the block. Anchoring on
    # the `-` instead of the key kept it open and scanned unrelated sections.
    # (template: blocks are intentionally out of scope -- see the key regex.)
    sibling_key = (
        "sources:\n"
        "  - query: |\n"
        "      SELECT * FROM info()\n"
        "    notebook:\n"
        "      - type: vql\n"
        "        template: |\n"
        "          /*\n"
        "          ## heading\n"
        "          */\n"
        "          SELECT 1\n")
    assert _query_block_comment_lines(sibling_key) == [], \
        "the query block must end at a sibling key, not run into later sections"


def test_the_two_artifacts_that_regressed_stay_fixed():
    """Both carried `#` comments and were dead on the server for it."""
    for name in ("tenRoot__IRIS__Timeline__Add.yaml", "IRIS__Sync__Asset.yaml"):
        path = os.path.join(BUNDLED, name)
        assert os.path.isfile(path), f"{name} is missing"
        assert _query_block_comment_lines(_read(path)) == [], \
            f"{name} regressed to `#` comments inside its query"


# --- 2. the image tag has to mean something ---------------------------------


def test_the_dockerfile_verifies_the_staged_binary_matches_the_tag():
    src = _read(DOCKERFILE)

    assert "velociraptor version" in src, (
        "the Dockerfile does not check the staged binary's version, so the "
        "image tag is a label with nothing behind it")
    assert "VELOCIRAPTOR_VERSION" in src, \
        "the check must compare against the tag the image is being given"
    assert "exit 1" in src, \
        "a positively-detected mismatch must fail the build, not just warn"


def test_the_version_check_does_not_fail_on_its_own_malfunction():
    """A guard against a rare condition must not become a common cause of
    broken builds. If the version cannot be read at all, warn and continue."""
    src = _read(DOCKERFILE)
    start = src.index("velociraptor version")
    block = src[start:start + 1600]
    assert 'if [ -z "$staged" ]' in block, \
        "no branch for 'could not read the version'"
    unreadable = block[block.index('if [ -z "$staged" ]'):]
    unreadable = unreadable[:unreadable.index("elif")]
    assert "exit 1" not in unreadable, \
        "an unreadable version must warn and continue, never fail the build"
    assert "WARNING" in unreadable, \
        "an unreadable version should say so"


def test_the_check_runs_after_the_binary_is_made_executable():
    """Ordering bug that would make the check silently useless: run it before
    the chmod and it can never read a version, so it warns forever."""
    src = _read(DOCKERFILE)
    assert src.index("chmod +x /opt/velociraptor/linux/velociraptor") < \
        src.index("velociraptor version"), \
        "the version check runs before the chmod, so it can never succeed"


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
