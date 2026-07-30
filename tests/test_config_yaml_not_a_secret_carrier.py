"""config.yaml holds real credentials, so it must not travel.

That file accumulates `options.github_token` (a real GitHub PAT), the dashboard
login and every module password. Three separate paths were carrying it somewhere
it should never have been:

  1. INTO THE BACKEND IMAGE. modules/backend/Dockerfile did `COPY config.yaml
     /app/config.yaml` — twice. Every locally-built image therefore had the build
     host's live credentials in a layer, recoverable with:

         docker run --rm --entrypoint sh <image> -c 'cat /app/config.yaml'

     Verified on the running appliance's own image: it returned
     `github_token: ghp_...`. Image layers get saved, pushed and shared, and
     none of that leaves an audit trail. Nothing was gained by it either — at
     runtime modules/backend/docker-compose.yaml bind-mounts the operator's real
     config.yaml over that exact path, so the baked copy was only ever a
     build-time input for install_deps.py.

  2. INTO GIT. config.yaml was tracked, so it sat one careless `git add
     config.yaml` away from being published. (It also meant the installer's
     yaml.dump rewrite destroyed ~200 lines of documentation comments on every
     install, because the tracked file and the operator's file were the same
     file.)

  3. TO EVERY LOCAL ACCOUNT. It was mode 664, and install.sh's
     "chmod 644 everything that isn't a secret" sweep did not exclude it — so
     any user on the box could read the PAT.

What ships now is config.yaml.example, with empty secrets. lib/config.sh seeds
config.yaml from it on a fresh checkout, and the image is built from the example.

Static assertions over the source tree, plus git's own view of what is tracked.

Run: docker exec intact_backend python3 /app/workdir/tests/test_config_yaml_not_a_secret_carrier.py
"""

import os
import re
import subprocess
import sys

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
DOCKERFILE = os.path.join(REPO, "modules", "backend", "Dockerfile")
EXAMPLE = os.path.join(REPO, "config.yaml.example")
GITIGNORE = os.path.join(REPO, ".gitignore")
CONFIG_SH = os.path.join(REPO, "lib", "config.sh")
INSTALL_SH = os.path.join(REPO, "install.sh")
UPGRADE = os.path.join(REPO, "modules", "backend", "services", "upgrade", "intact.py")


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _uncommented(text, marker="#"):
    return "\n".join(ln for ln in text.splitlines()
                     if not ln.lstrip().startswith(marker))


def _git(*args):
    """Run git in the repo, or return None if git can't answer.

    The test container runs as root while the checkout is owned by the operator,
    so git refuses with "detected dubious ownership" unless safe.directory is
    set. That is an environment quirk, not a product regression — treat it as
    "unknown" and let the caller skip rather than fail the suite.
    """
    try:
        r = subprocess.run(["git", "-C", REPO, *args],
                           capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip()


# --- 1. the image must not carry it -----------------------------------------


def test_the_dockerfile_never_copies_the_live_config():
    """The regression: `COPY config.yaml` bakes the build host's credentials
    into a distributable image layer."""
    body = _uncommented(_read(DOCKERFILE))
    bad = [ln.strip() for ln in body.splitlines()
           if re.match(r'^\s*COPY\s+config\.yaml\s', ln)]
    assert not bad, (
        f"Dockerfile copies the operator's live config.yaml into the image, "
        f"which bakes in the GitHub PAT and every module password: {bad}")


def test_the_dockerfile_copies_the_template_instead():
    body = _uncommented(_read(DOCKERFILE))
    assert re.search(r'^\s*COPY\s+config\.yaml\.example\s+/app/config\.yaml',
                     body, re.MULTILINE), \
        "the Dockerfile no longer provides /app/config.yaml at all — " \
        "install_deps.py reads it at build time"


def test_install_deps_still_has_a_config_to_read():
    """It decides which module dependencies to install; without a config at that
    path the build either fails or silently installs nothing."""
    body = _uncommented(_read(DOCKERFILE))
    deps = [ln for ln in body.splitlines() if "install_deps.py" in ln]
    assert deps, "install_deps.py is no longer invoked"
    copy_line = None
    for line in body.splitlines():
        if re.match(r'^\s*COPY\s+config\.yaml\.example\s+/app/config\.yaml', line):
            copy_line = body.index(line)
            break
    assert copy_line is not None and copy_line < body.index(deps[0]), \
        "the template is copied AFTER install_deps.py runs, so the build has no config"


# --- 2. git must not carry it ------------------------------------------------


def test_config_yaml_is_not_tracked():
    """Untracked, so no `git add` can publish the PAT."""
    tracked = _git("ls-files", "config.yaml")
    if tracked is None:
        print("  (skipped — git could not answer in this container)")
        return
    assert not tracked, \
        "config.yaml is tracked again; it holds the GitHub PAT and every " \
        "module password"


def test_config_yaml_is_gitignored():
    body = _read(GITIGNORE)
    entries = [ln.strip() for ln in body.splitlines()
               if ln.strip() and not ln.lstrip().startswith("#")]
    assert "config.yaml" in entries, \
        "config.yaml is not in .gitignore, so it can be re-added by accident"
    assert "!config.yaml.example" in entries, \
        "the negation for config.yaml.example is missing — the template is what " \
        "ships, and 'config.yaml' would otherwise not match it but a future " \
        "glob might"


def test_the_template_exists_and_is_tracked():
    assert os.path.isfile(EXAMPLE), "config.yaml.example is missing — a fresh " \
                                    "clone has nothing to seed config.yaml from"
    tracked = _git("ls-files", "config.yaml.example")
    if tracked is None:
        print("  (skipped tracking check — git could not answer)")
        return
    assert tracked, "config.yaml.example is not tracked, so it won't ship"


def test_the_template_carries_no_real_secrets():
    """It IS committed, so anything real in here is published."""
    body = _read(EXAMPLE)
    assert not re.search(r'ghp_[A-Za-z0-9]{20,}', body), \
        "the shipped template contains a real-looking GitHub PAT"
    assert re.search(r"^\s*github_token:\s*''\s*$", body, re.MULTILINE), \
        "github_token in the template should be empty"
    # A real private key or long high-entropy literal has no business here.
    assert "BEGIN RSA PRIVATE KEY" not in body
    assert "BEGIN PRIVATE KEY" not in body


def test_the_template_still_drives_a_working_build():
    """install_deps.py keys off modules.*.enabled; if the template disabled
    everything, images would ship without module dependencies."""
    import yaml
    cfg = yaml.safe_load(_read(EXAMPLE))
    modules = cfg.get("modules") or {}
    enabled = [k for k, v in modules.items()
               if isinstance(v, dict) and v.get("enabled")]
    assert len(enabled) >= 5, (
        f"only {len(enabled)} modules are enabled in the template; the image is "
        f"built from it, so module dependencies would be missing: {enabled}")


def test_the_template_ships_the_first_login_flag():
    """A fresh install must land on the setup page, which is driven by this."""
    import yaml
    cfg = yaml.safe_load(_read(EXAMPLE))
    assert cfg.get("first_login") is True, \
        "the template must ship first_login: true so a fresh install can be claimed"


# --- 3. local accounts must not read it --------------------------------------


def test_the_installer_restricts_config_yaml_permissions():
    body = _read(INSTALL_SH)
    assert re.search(r'chmod 600 "\$\{SCRIPT_DIR\}/config\.yaml"', body), \
        "install.sh does not chmod 600 config.yaml — it was landing at 664, " \
        "readable by every local account, with a live PAT in it"


def test_the_644_sweep_excludes_config_yaml():
    """Otherwise the sweep undoes the chmod above on every install."""
    body = _read(INSTALL_SH)
    sweep_start = body.index('-exec chmod 644')
    sweep = body[max(0, sweep_start - 1200):sweep_start]
    assert 'config.yaml' in sweep, \
        "the chmod-644 sweep does not exclude config.yaml, so it will be made " \
        "world-readable again"


# --- seeding + the upgrade path ---------------------------------------------


def test_a_fresh_checkout_seeds_config_from_the_template():
    body = _read(CONFIG_SH)
    assert "config.yaml.example" in body, \
        "check_config() cannot seed config.yaml, so a fresh clone fails to install"
    assert "chmod 600" in body, \
        "the seeded config.yaml is not locked down at creation"


def test_the_upgrade_prefers_the_template_but_tolerates_old_packages():
    """Version pins are merged from the release's config. Current releases ship
    only the template; packages built before this change still ship config.yaml."""
    body = _read(UPGRADE)
    # Anchor on the ASSIGNMENT, not the first mention — `new_config_path` also
    # appears in merge_versions_from_new_config's own signature and docstring
    # several hundred lines earlier.
    start = body.index("new_config_path = None")
    window = body[start:start + 700]
    assert "config.yaml.example" in window, \
        "the upgrade still looks only for config.yaml in the release package, " \
        "so version pins would stop updating"
    assert re.search(r"'config\.yaml\.example',\s*'config\.yaml'", window), \
        "the fallback order should try the template first, then plain " \
        "config.yaml for packages built before this change"


def test_the_package_build_does_not_exclude_the_template():
    """The release package ships source/intact/; if the example were filtered out
    the upgrade would have no version pins to merge."""
    pkg = os.path.join(REPO, "modules", "backend", "services", "upgrade", "package.py")
    body = _read(pkg)
    for match in re.finditer(r"ignore_patterns\(([^)]*)\)", body, re.DOTALL):
        patterns = match.group(1)
        assert "config.yaml" not in patterns, \
            f"the packaging step filters out config.yaml*: {patterns}"


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
