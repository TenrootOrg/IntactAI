"""The copyable Prepare-Package bash must stay true to what the backend does.

The Prepare dialog now offers a bash script that fetches the release package by
hand. It exists for the operator most likely to need a package: the one whose
appliance cannot fetch it. No route to GitHub, a wedged backend (every /api/
call 502ing -- seen 2026-08-03), an exhausted API quota, or an air-gapped site
where the download has to happen on a laptop and be carried in.

It is only a few lines because Prepare is DOWNLOAD-ONLY -- it fetches the
CI-built artifact attached to the release and verifies it; nothing is compiled
on the appliance. That is exactly why the script can be trusted to be
equivalent, and exactly why it rots the moment the asset layout changes.

The asset contract lives in services/upgrade/download.py:

  * `intact-upgrade-<tag>.tar.gz`                      the package
  * `intact-upgrade-<tag>.tar.gz.part-00`, `.part-01`  when it exceeds GitHub's
                                                       2 GB per-asset limit
  * `intact-upgrade-<tag>.tar.gz.sha256`               whole-file checksum

These tests pin the script against that contract, so a change to one without
the other fails here rather than in an operator's terminal at the worst moment.

Run: docker exec intact_backend python /app/workdir/tests/test_prepare_manual_script.py
"""

import os
import re
import sys

REPO = os.environ.get("INTACT_PATH") or os.path.dirname(
    os.path.dirname(os.path.abspath(__file__)))
STORE = open(os.path.join(REPO, "modules", "nginx", "html", "js", "stores",
                          "settings.js")).read()
DOWNLOAD_PY = open(os.path.join(REPO, "modules", "backend", "services",
                                "upgrade", "download.py")).read()
SETTINGS_HTML = open(os.path.join(REPO, "modules", "nginx", "html", "partials",
                                  "settings.html")).read()

def _fn_body(name):
    body = STORE[STORE.index(name + "()"):]
    return body[:body.index("\n        },")]


SCRIPT = _fn_body("prepareManualScript")
SCRIPT_PS = _fn_body("prepareManualScriptPs")

# The generated script documents itself -- "no docker needed on this machine",
# "NOT browser_download_url". Asserting over the raw text matches those
# explanations rather than the commands, so a script that SAYS the right thing
# passes while DOING the wrong thing. Strip both the JS comments and the bash
# comment lines inside the emitted strings, and assert on what will actually
# execute.
def _commands_only(text):
    out = []
    for line in text.splitlines():
        st = line.strip()
        if st.startswith("//"):                     # JS comment
            continue
        m = re.match(r"^'(.*)',?$", st)             # an emitted bash line
        if m:
            bash = m.group(1)
            if bash.lstrip().startswith("#"):       # bash comment
                continue
            out.append(bash)
        else:
            out.append(st)
    return "\n".join(out)


COMMANDS = _commands_only(SCRIPT)


def test_the_generator_exists_and_is_wired_to_the_dialog():
    assert "prepareManualScript()" in SETTINGS_HTML, (
        "the manual script is no longer rendered in the Prepare dialog")
    assert "cliCopy(" in SETTINGS_HTML and "prepareManualScript()" in SETTINGS_HTML, (
        "there is no copy button — the operator would have to hand-select "
        "multi-line text, which is the whole thing this replaces")


def test_the_base_asset_name_matches_the_backend():
    """download.py builds `intact-upgrade-{tag}.tar.gz`. If that ever changes,
    the script silently downloads nothing and reports 'no package assets'."""
    assert 'base = f"intact-upgrade-{tag}.tar.gz"' in DOWNLOAD_PY, (
        "download.py's asset name changed — update the manual script to match")
    assert 'intact-upgrade-$TAG.tar.gz' in SCRIPT, (
        "the manual script no longer builds the same asset name as download.py")


def test_it_handles_the_split_parts():
    """Packages over GitHub's 2 GB per-asset limit ship as .part-NN. A script
    that only looked for the plain .tar.gz would find nothing at all for the
    releases most likely to need a manual fetch -- the big ones."""
    assert "part-" in DOWNLOAD_PY, "download.py no longer mentions split parts"
    assert '.part-*' in SCRIPT, (
        "the manual script does not reassemble split assets")


def test_the_parts_are_concatenated_in_order():
    """`cat *.part-*` in shell glob order happens to be sorted today, but the
    script says so explicitly -- parts joined in any other order still produce
    a file, just not a valid one."""
    assert "sort" in SCRIPT, (
        "parts are concatenated without an explicit sort")


def test_both_verify_the_checksum():
    """The one step that must never be dropped for convenience: this file gets
    carried into an air-gapped site on a USB stick.

    Asserts the BEHAVIOUR, not one spelling of it. The bash version moved off
    `sha256sum -c` to an explicit compare so a mismatch can print want-vs-got
    instead of sha256sum's terse 'FAILED'."""
    b = _commands_only(SCRIPT)
    assert "sha256sum" in b and "MISMATCH" in b, (
        "the bash script no longer compares the package checksum")
    ps = _commands_only(SCRIPT_PS)
    assert "Get-FileHash" in ps and "MISMATCH" in ps, (
        "the PowerShell script no longer compares the package checksum")


def test_it_uses_the_api_asset_url_not_browser_download_url():
    """Private-repo assets 404 on browser_download_url without a session; the
    API url plus `Accept: application/octet-stream` is the only route that
    works with a token."""
    assert "application/octet-stream" in COMMANDS, (
        "the script does not request octet-stream, so a private-repo asset "
        "download returns JSON metadata instead of the file")
    assert "browser_download_url" not in COMMANDS, (
        "the script uses browser_download_url, which does not work for a "
        "private repository")


def test_it_demands_a_token_up_front():
    """The repo is private, so even LISTING the release needs auth. Failing at
    the first line with an actionable message beats failing three GB in."""
    assert "GITHUB_TOKEN" in SCRIPT
    assert ':?' in SCRIPT or 'exit' in SCRIPT, (
        "the script does not fail fast when GITHUB_TOKEN is unset")


def test_it_needs_nothing_from_the_appliance():
    """The point is that it runs on a laptop. Any of these would defeat that."""
    for forbidden in ("docker ", "docker-compose", "/app/", "intact_backend"):
        assert forbidden not in COMMANDS, (
            f"the manual script references {forbidden!r} — it is supposed to "
            f"run on a machine with no Intact.AI install")


def test_the_default_tag_is_a_real_release():
    """A `<RELEASE-TAG>` placeholder failed forty lines later as "Illegal
    characters in path" from Get-Content, because < and > cannot appear in a
    Windows filename. Reported 2026-08-03 from a real paste. A concrete tag
    runs as-is, and the inline note says to change it."""
    for src, label in ((SCRIPT, "bash"), (SCRIPT_PS, "powershell")):
        assert "<RELEASE-TAG>" not in src, (
            f"{label} still emits an angle-bracket placeholder — it produces an "
            f"illegal Windows filename and fails late and unclearly")
        assert "CHANGE to the release you want" in src, (
            f"{label} has no inline instruction to change the tag")


def test_powershell_does_not_interpolate_the_token_into_its_own_error():
    """`throw "set $env:GITHUB_TOKEN first"` expands the variable INSIDE the
    message, so an unset token printed "set  first" — advice with the crucial
    word deleted. Reported from a real paste 2026-08-03."""
    line = next((l for l in SCRIPT_PS.splitlines()
                 if "GITHUB_TOKEN first" in l), "")
    assert line, "the token check message is gone"
    assert "throw '" in line or "\\'" in line, (
        "the token error is double-quoted, so PowerShell expands "
        "$env:GITHUB_TOKEN inside the message and prints 'set  first'")


def test_powershell_runs_as_one_unit_when_pasted():
    """Pasted into an interactive prompt, a bare script runs line BY line: a
    `throw` aborts one statement and every later line still runs against
    half-initialised state, cascading errors that hide the real one. A script
    block is buffered to the closing brace and runs atomically."""
    assert "'& {'," in SCRIPT_PS, (
        "the PowerShell script is not wrapped in & { } — pasting it will run "
        "line-by-line and a failure will cascade instead of stopping")


def test_both_handle_a_failed_api_call():
    """A 401 left $rel null and the next line died with 'cannot call a method
    on a null-valued expression' — an error about PowerShell semantics, not
    about the token being wrong."""
    assert "try {" in SCRIPT_PS and "catch" in SCRIPT_PS, (
        "PowerShell does not catch the release lookup failure")
    for src, label in ((SCRIPT, "bash"), (SCRIPT_PS, "powershell")):
        assert "401" in src and "404" in src, (
            f"{label} does not explain what a 401 or 404 actually means")


def test_both_print_the_hash_on_success():
    """So the operator can compare it against the release without re-hashing."""
    for src, label in ((SCRIPT, "bash"), (SCRIPT_PS, "powershell")):
        assert "sha256 $" in src or "sha256 $got" in src, (
            f"{label} does not print the verified hash")


def test_a_powershell_twin_exists():
    """Windows operators are a large share of the people who would ever run
    this by hand, and telling them to install WSL or Git Bash first defeats the
    point of a fallback."""
    assert "prepareManualScriptPs" in STORE, "no PowerShell variant"
    assert "prepareManualScriptPs()" in SETTINGS_HTML, (
        "the PowerShell variant is not reachable from the dialog")


def test_powershell_needs_nothing_installed():
    """It is the only genuinely dependency-free option: PowerShell 5+ parses
    JSON and hashes natively. Reaching for curl or jq there would throw that
    away."""
    ps = _commands_only(SCRIPT_PS)
    assert "ConvertFrom-Json" in ps or "Invoke-RestMethod" in ps, (
        "PowerShell script does not use native JSON parsing")
    assert "Get-FileHash" in ps, "PowerShell script does not verify the checksum"
    for dep in ("curl ", "jq ", "python3", "sha256sum"):
        assert dep not in ps, (
            f"PowerShell script shells out to {dep!r} — it should need nothing "
            f"installed")


def test_powershell_handles_the_same_traps():
    ps = _commands_only(SCRIPT_PS)
    assert "application/octet-stream" in ps, "private-repo asset download will fail"
    assert "Sort-Object" in ps, "split parts joined without an explicit sort"


def test_bash_does_not_hard_require_python():
    """'Runs anywhere' is weakened by a hard python3 dependency; jq is just as
    common and either will do."""
    cmds = _commands_only(SCRIPT)
    assert "command -v jq" in cmds, "bash script no longer tries jq first"
    assert "command -v python3" in cmds, "bash script has no python3 fallback"


def test_the_script_is_not_hidden_behind_a_disclosure():
    """The operator who needs this is the one whose dialog is already failing.
    Hiding it behind a click assumes the dialog works."""
    assert "<details" not in SETTINGS_HTML, (
        "the manual script is behind a <details> again — it must be visible "
        "without interaction")
    assert '<textarea readonly' in SETTINGS_HTML, (
        "the script is not in a selectable textbox")


def test_the_note_no_longer_claims_it_builds_images():
    """Prepare downloads a prebuilt package; it has not built images on the box
    since it became download-only."""
    assert "download Docker images and binaries for selected modules" not in SETTINGS_HTML, (
        "the yellow Note still describes the old build-on-box behaviour")


def test_the_dialog_no_longer_claims_module_selection():
    """Prepare has no module picker: it downloads the whole CI package and the
    operator chooses on import. The old subtitle said otherwise."""
    assert "Select modules to include in the offline upgrade package" not in SETTINGS_HTML, (
        "the Prepare dialog still says it selects modules for the package — it "
        "downloads the whole thing and selection happens at import")


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
