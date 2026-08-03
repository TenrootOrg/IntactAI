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

SCRIPT = STORE[STORE.index("prepareManualScript()"):]
SCRIPT = SCRIPT[:SCRIPT.index("\n        },")]

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
    assert "cliCopy($store.settings.prepareManualScript()" in SETTINGS_HTML, (
        "there is no copy button — the operator would have to select multi-line "
        "text out of a <pre>, which is the whole thing this replaces")


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


def test_it_verifies_the_checksum():
    """The one step that must never be dropped for convenience: this file gets
    carried in on a USB stick to an air-gapped site."""
    assert "sha256sum -c" in SCRIPT, (
        "the manual script no longer verifies the package checksum")


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
