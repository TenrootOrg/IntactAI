"""We patch a vendor container. These are the tests that keep that honest.

Timesketch ships as an image we do not build, so adding an LLM provider means
writing into the running container's site-packages and appending imports to a
file upstream owns. Three things make that safe, and each one is easy to
break silently:

  1. The patch must reach EVERY container that runs the Timesketch image. Add
     a fifth service, forget the prologue, and one frontend quietly has a
     different provider registry than the other three.
  2. The patch must never be able to stop Timesketch from starting.
     LLMManager.register_provider() raises ValueError on a duplicate name and
     that propagates out of timesketch.wsgi -- the naive failure mode here is
     not "feature missing", it is four containers crash-looping.
  3. The two operator-facing notes must stay notes. install.sh's log_warn
     feeds the ATTENTION block; the upgrade's "error" level demotes a
     completed run to failed. Either would turn "this is working as designed"
     into "something is wrong".

Everything here is offline and stack-free: compose is parsed, shell and
Python are read as text or AST, and apply.sh is exercised against a fake
package tree in a temp dir. Runs under `--network none` in CI.

Run: docker exec intact_backend python3 /app/workdir/tests/test_timesketch_llm_providers.py
"""

import ast
import json
import os
import re
import subprocess
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
TS_DIR = os.path.join(REPO, "modules", "timesketch")
COMPOSE = os.path.join(TS_DIR, "docker-compose.yaml")
PROVIDER_DIR = os.path.join(TS_DIR, "llm_providers")
APPLY_SH = os.path.join(PROVIDER_DIR, "apply.sh")
PROVIDERS = ("openrouter", "litellm_proxy")

VENDOR_IMAGE_PREFIX = "us-docker.pkg.dev/osdfir-registry/timesketch"
MOUNT = "./llm_providers:/opt/intact/llm_providers:ro"

sys.path.insert(0, os.path.join(REPO, "scripts", "ci"))
import check_timesketch_provider_drift as DRIFT  # noqa: E402


def _read(path):
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def _compose():
    import yaml
    return yaml.safe_load(_read(COMPOSE))


def _vendor_services():
    """Every service running the Timesketch image, by name."""
    services = _compose()["services"]
    return {name: spec for name, spec in services.items()
            if str(spec.get("image", "")).startswith(VENDOR_IMAGE_PREFIX)}


# --- the patch must reach every container that runs the image ---------------


def test_every_vendor_image_service_carries_the_prologue():
    """The 'someone added a fifth service' test.

    Keyed on the IMAGE, not on a hardcoded service list, so a new Timesketch
    container cannot be added without either getting the prologue or failing
    here.
    """
    found = _vendor_services()
    assert len(found) >= 4, f"expected at least 4 vendor-image services, got {sorted(found)}"

    for name, spec in sorted(found.items()):
        assert spec.get("entrypoint") == ["/bin/bash", "-c"], (
            f"{name}: entrypoint must be the bash -c form for the prologue to "
            f"run, got {spec.get('entrypoint')!r}")

        command = spec.get("command")
        assert isinstance(command, list) and len(command) == 1, (
            f"{name}: expected a single inline command block, got {command!r}")
        body = command[0]
        assert "llm_providers/apply.sh" in body, \
            f"{name}: the command block never invokes apply.sh"

        volumes = [str(v) for v in spec.get("volumes", [])]
        assert MOUNT in volumes, \
            f"{name}: missing the read-only payload mount {MOUNT!r}; got {volumes}"


def test_the_prologue_cannot_block_startup():
    """A missing payload must degrade to a no-op, not to a container that
    will not start. On a partially-applied upgrade docker bind-mounts an
    empty directory, so this is a real state, not a hypothetical."""
    for name, spec in sorted(_vendor_services().items()):
        body = spec["command"][0]

        line = [ln for ln in body.splitlines() if "apply.sh" in ln]
        assert len(line) == 1, f"{name}: expected exactly one apply.sh line"
        line = line[0].strip()

        assert line.startswith("[ -r "), \
            f"{name}: apply.sh must be guarded by a readability test, got: {line}"
        assert line.endswith("; true"), (
            f"{name}: the guard must end in '; true' so a false test cannot "
            f"leave a non-zero status behind, got: {line}")
        assert "bash /opt/intact/llm_providers/apply.sh" in line, (
            f"{name}: invoke via `bash <path>`, never ./apply.sh -- "
            f"install.sh's fix_source_permissions chmods every tracked file "
            f"to 644, so the exec bit does not survive an install")

        assert spec["entrypoint"] != [APPLY_SH], \
            f"{name}: apply.sh must never BE the entrypoint"
        assert "apply.sh" not in str(spec["entrypoint"]), \
            f"{name}: apply.sh must never appear in the entrypoint"


def test_the_prologue_still_execs_the_vendor_entrypoint():
    """Whatever else it does, each service must still start what it started
    before -- with the same argument."""
    known = {
        "timesketch-web": "timesketch-web",
        "timesketch-web-legacy": "timesketch-web-legacy",
        "timesketch-web-v3": "timesketch-web-v3",
        "timesketch-worker": "timesketch-worker",
    }
    for name, spec in sorted(_vendor_services().items()):
        body = spec["command"][0]
        last = [ln.strip() for ln in body.splitlines() if ln.strip()][-1]
        assert last.startswith("exec /docker-entrypoint.sh "), \
            f"{name}: the block must end by exec'ing the vendor entrypoint, got: {last}"
        if name in known:
            assert last == f"exec /docker-entrypoint.sh {known[name]}", \
                f"{name}: the entrypoint argument changed: {last}"


# --- apply.sh must not be able to break the container ------------------------


def test_apply_sh_is_failsafe_by_construction():
    src = _read(APPLY_SH)

    for forbidden in ("set -e", "set -u", "set -o pipefail", "set -eu"):
        for line in src.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            assert not stripped.startswith(forbidden), (
                f"apply.sh must not use `{forbidden}` -- any unexpected "
                f"non-zero would abort before Timesketch starts")

    assert src.rstrip().endswith("exit 0"), \
        "apply.sh must end in `exit 0`"

    # Every early return has to be exit 0 too, not exit 1.
    bad = [ln.strip() for ln in src.splitlines()
           if re.match(r"^\s*exit\s+[1-9]", ln)]
    assert not bad, f"apply.sh has non-zero exits: {bad}"


def test_apply_sh_never_hardcodes_a_python_version():
    """The image is on 3.14 today and was on 3.12 before. A literal path
    would have broken on the very first upgrade."""
    src = _read(APPLY_SH)
    hits = re.findall(r"python3\.\d+", src)
    hits = [h for h in hits if h not in ("python3.NN",)]
    assert not hits, (
        f"apply.sh hardcodes {sorted(set(hits))}; resolve the package with "
        f"find_spec plus a python* glob instead")
    assert "find_spec" in src, "apply.sh should locate the package via find_spec"


def test_apply_sh_parses_under_bash():
    result = subprocess.run(["bash", "-n", APPLY_SH],
                            capture_output=True, text=True)
    assert result.returncode == 0, f"apply.sh does not parse: {result.stderr}"


# --- apply.sh behaviour, against a fake package tree -------------------------


def _sandbox():
    """A fake providers package: {root, pkg, contrib}."""
    root = tempfile.mkdtemp(prefix="tslp_")
    pkg = os.path.join(root, "providers")
    os.makedirs(os.path.join(pkg, "contrib"))
    with open(os.path.join(pkg, "__init__.py"), "w") as handle:
        handle.write("from timesketch.lib.llms.providers import ollama\n")
    open(os.path.join(pkg, "contrib", "__init__.py"), "w").close()
    return root, pkg


def _run_apply(pkg, src=PROVIDER_DIR):
    env = dict(os.environ)
    env["INTACT_LLM_PROVIDERS_PKG"] = pkg
    env["INTACT_LLM_PROVIDERS_SRC"] = src
    env["INTACT_LLM_PROVIDERS_LOG"] = os.path.join(pkg, "apply.log")
    result = subprocess.run(["bash", APPLY_SH], capture_output=True,
                            text=True, env=env)
    return result


def test_apply_sh_installs_and_registers_both_providers():
    _root, pkg = _sandbox()
    result = _run_apply(pkg)
    assert result.returncode == 0, result.stderr

    for name in PROVIDERS:
        assert os.path.isfile(os.path.join(pkg, "contrib", f"{name}.py")), \
            f"{name} was not copied into contrib/"

    init = _read(os.path.join(pkg, "__init__.py"))
    assert "from timesketch.lib.llms.providers import ollama" in init, \
        "upstream's own imports must be preserved verbatim"
    for name in PROVIDERS:
        assert f"import {name}" in init, f"{name} was never imported"

    # The appended block has to be valid Python or the container dies on
    # import -- which is the whole failure mode this design exists to avoid.
    ast.parse(init)


def test_every_appended_import_is_individually_guarded():
    """An unguarded import of a provider that no longer matches the interface
    aborts the import of timesketch.wsgi and crash-loops the container."""
    _root, pkg = _sandbox()
    _run_apply(pkg)
    tree = ast.parse(_read(os.path.join(pkg, "__init__.py")))

    guarded = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        handlers_ok = any(
            isinstance(h.type, ast.Name) and h.type.id == "Exception"
            for h in node.handlers)
        if not handlers_ok:
            continue
        for stmt in node.body:
            if isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    guarded.add(alias.name)

    for name in PROVIDERS:
        assert name in guarded, \
            f"{name} is imported without a try/except Exception guard"


def test_apply_sh_is_idempotent():
    _root, pkg = _sandbox()
    _run_apply(pkg)
    first = _read(os.path.join(pkg, "__init__.py"))
    _run_apply(pkg)
    second = _read(os.path.join(pkg, "__init__.py"))
    assert first == second, "a second run modified __init__.py again"
    assert second.count("intact.ai: contrib LLM providers") == 1, \
        "the import block was appended more than once"


def test_apply_sh_refuses_to_clobber_an_upstream_provider():
    """If upstream ships its own contrib/openrouter.py, ours must not
    overwrite it and must not be imported -- upstream's __init__ owns it, and
    importing both would hit register_provider's duplicate-name ValueError."""
    _root, pkg = _sandbox()
    upstream = os.path.join(pkg, "contrib", "openrouter.py")
    with open(upstream, "w") as handle:
        handle.write("# upstream's own openrouter provider\n")

    result = _run_apply(pkg)
    assert result.returncode == 0

    assert _read(upstream) == "# upstream's own openrouter provider\n", \
        "upstream's file was overwritten"
    init = _read(os.path.join(pkg, "__init__.py"))
    assert "import openrouter" not in init, \
        "our openrouter import was added despite upstream owning the module"
    assert "import litellm_proxy" in init, \
        "the uncontested provider should still have been installed"


def test_apply_sh_is_a_noop_when_the_payload_is_missing():
    """The partially-applied-upgrade case: compose arrived, payload did not,
    docker mounted an empty directory."""
    _root, pkg = _sandbox()
    empty = tempfile.mkdtemp(prefix="tslp_empty_")
    before = _read(os.path.join(pkg, "__init__.py"))

    result = _run_apply(pkg, src=empty)
    assert result.returncode == 0, result.stderr
    assert _read(os.path.join(pkg, "__init__.py")) == before, \
        "__init__.py was modified even though no provider could be installed"


def test_apply_sh_survives_a_missing_package_tree():
    result = subprocess.run(
        ["bash", APPLY_SH], capture_output=True, text=True,
        env=dict(os.environ,
                 INTACT_LLM_PROVIDERS_PKG="/nonexistent/providers",
                 INTACT_LLM_PROVIDERS_SRC=PROVIDER_DIR,
                 INTACT_LLM_PROVIDERS_LOG=os.path.join(
                     tempfile.mkdtemp(prefix="tslp_log_"), "apply.log")))
    assert result.returncode == 0, \
        "a missing package tree must be a no-op, not a failure"


# --- the payload itself ------------------------------------------------------


def test_each_provider_matches_the_upstream_contract():
    """Parsed, never imported: importing would need requests and flask, and
    would run the module-level register_provider() call."""
    for name in PROVIDERS:
        tree = ast.parse(_read(os.path.join(PROVIDER_DIR, f"{name}.py")))

        classes = [n for n in tree.body if isinstance(n, ast.ClassDef)]
        subclasses = [c for c in classes if any(
            isinstance(b, ast.Attribute) and b.attr == "LLMProvider"
            for b in c.bases)]
        assert len(subclasses) == 1, \
            f"{name}: expected exactly one interface.LLMProvider subclass"
        cls = subclasses[0]

        names = [n for n in cls.body
                 if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "NAME"
                         for t in n.targets)]
        assert names, f"{name}: the provider class has no NAME"
        assert isinstance(names[0].value, ast.Constant) and \
            isinstance(names[0].value.value, str), \
            f"{name}: NAME must be a string literal"

        generate = [n for n in cls.body
                    if isinstance(n, ast.FunctionDef) and n.name == "generate"]
        assert generate, f"{name}: no generate() method"
        args = [a.arg for a in generate[0].args.args]
        assert args[:3] == ["self", "prompt", "response_schema"], \
            f"{name}: generate signature drifted from the interface: {args}"

        src = _read(os.path.join(PROVIDER_DIR, f"{name}.py"))
        assert "manager.LLMManager.register_provider" in src, \
            f"{name}: never registers itself with the manager"


def test_provider_names_do_not_collide_with_upstream():
    baseline = json.loads(_read(DRIFT.DEFAULT_BASELINE))
    known = set(baseline.get("known_upstream_provider_names", []))
    for name in PROVIDERS:
        assert name not in known, (
            f"{name} collides with an upstream provider module; "
            f"register_provider() raises ValueError on duplicates")


# --- the drift check ---------------------------------------------------------


def test_baseline_covers_exactly_the_watch_list():
    baseline = json.loads(_read(DRIFT.DEFAULT_BASELINE))
    assert set(baseline["files"]) == set(DRIFT.WATCHED), (
        "the baseline and the script's WATCHED list disagree -- a watched "
        "file was added without re-stamping, or vice versa.\n"
        f"  only in baseline: {sorted(set(baseline['files']) - set(DRIFT.WATCHED))}\n"
        f"  only in WATCHED : {sorted(set(DRIFT.WATCHED) - set(baseline['files']))}")


def test_the_watch_list_covers_what_we_actually_depend_on():
    """The two files we mutate or subclass must be watched at contract tier."""
    for path in ("timesketch/lib/llms/providers/__init__.py",
                 "timesketch/lib/llms/providers/interface.py",
                 "timesketch/lib/llms/providers/manager.py"):
        assert DRIFT.WATCHED[path][0] == "contract", \
            f"{path} must be watched at contract tier"
    for name in PROVIDERS:
        path = f"timesketch/lib/llms/providers/contrib/{name}.py"
        assert DRIFT.WATCHED[path][0] == "must_not_exist", \
            f"{path} must be watched so an upstream collision is caught"


def test_drift_comparison_is_pure():
    """No network, no disk -- just baseline in, verdict out."""
    baseline = {
        "verified_upstream_version": "20260630",
        "files": {
            "timesketch/lib/llms/providers/__init__.py": {"sha256": "aaa"},
            "timesketch/lib/llms/providers/interface.py": {"sha256": "bbb"},
            "timesketch/lib/llms/providers/manager.py": {"sha256": "ccc"},
        },
    }
    watched = {
        "timesketch/lib/llms/providers/__init__.py": ("contract", "we append here"),
        "timesketch/lib/llms/providers/interface.py": ("contract", "we subclass this"),
        "timesketch/lib/llms/providers/manager.py": ("contract", "we register here"),
        "timesketch/lib/llms/providers/contrib/openrouter.py": ("must_not_exist", "collision"),
    }
    unchanged = {
        "timesketch/lib/llms/providers/__init__.py": "aaa",
        "timesketch/lib/llms/providers/interface.py": "bbb",
        "timesketch/lib/llms/providers/manager.py": "ccc",
    }

    clean = DRIFT.compare(baseline, unchanged, watched=watched)
    assert clean["drift"] is False, clean

    changed = DRIFT.compare(baseline, dict(unchanged, **{
        "timesketch/lib/llms/providers/interface.py": "DIFFERENT"}), watched=watched)
    assert changed["drift"] is True
    assert [f["kind"] for f in changed["findings"]] == ["changed"]
    assert changed["findings"][0]["path"].endswith("interface.py")

    collision = DRIFT.compare(baseline, dict(unchanged, **{
        "timesketch/lib/llms/providers/contrib/openrouter.py": "ddd"}), watched=watched)
    assert collision["drift"] is True
    assert collision["findings"][0]["kind"] == "appeared", collision

    removed = dict(unchanged)
    del removed["timesketch/lib/llms/providers/manager.py"]
    gone = DRIFT.compare(baseline, removed, watched=watched)
    assert gone["drift"] is True
    assert gone["findings"][0]["kind"] == "removed", gone


def test_an_unbaselined_watched_file_is_reported_not_ignored():
    """Adding to WATCHED without re-stamping must not read as 'no drift'."""
    watched = {"timesketch/lib/llms/providers/manager.py": ("contract", "x")}
    result = DRIFT.compare({"files": {}}, {"timesketch/lib/llms/providers/manager.py": "z"},
                           watched=watched)
    assert result["drift"] is True
    assert result["findings"][0]["kind"] == "unbaselined"


def test_the_pinned_version_is_read_from_config_yaml():
    version = DRIFT.read_pinned_version(os.path.join(REPO, "config.yaml"))
    assert re.match(r"^[A-Za-z0-9._-]+$", version), version
    # Must come from the versions: block, not from modules.timesketch.enabled.
    assert version not in ("true", "false", "True", "False"), \
        f"read the wrong key: {version}"


def test_a_tarball_member_cannot_escape_via_path_traversal():
    import io
    import tarfile
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for evil in ("/etc/passwd", "../../../etc/shadow"):
            data = b"pwned"
            info = tarfile.TarInfo(evil)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
        good = b"real content"
        info = tarfile.TarInfo(
            "timesketch-1/timesketch/lib/llms/providers/manager.py")
        info.size = len(good)
        tar.addfile(info, io.BytesIO(good))
    buf.seek(0)
    found = DRIFT.read_tarball(buf)
    assert set(found) == {"timesketch/lib/llms/providers/manager.py"}, found


# --- the notes must stay notes ----------------------------------------------


def test_the_install_note_cannot_reach_the_attention_block():
    """log_warn feeds INSTALL_WARNINGS, which prints the ATTENTION block and
    turns the summary banner yellow. This note must use neither, and its text
    must dodge the tokens record_child_output_issue() scrapes for.

    The token list is parsed out of common.sh rather than hardcoded, so this
    test tracks the scraper if it grows.
    """
    common = _read(os.path.join(REPO, "lib", "common.sh"))
    modules = _read(os.path.join(REPO, "lib", "modules.sh"))

    # Anchor on the DEFINITION at column 0 -- the name also appears in
    # record_install_note's comment, earlier in the file.
    scraper = common[common.index("\nrecord_child_output_issue() {"):]
    scraper = scraper[:scraper.index("\n}")]
    tokens = re.findall(r'== \*"([^"]+)"\*', scraper)
    assert len(tokens) >= 5, \
        f"could not parse the scraper's tokens out of common.sh (got {tokens})"

    note = modules[modules.index("record_timesketch_llm_provider_note()"):]
    note = note[:note.index("\ndeploy_timesketch()")]

    body = note[note.index("record_install_note"):]
    for token in tokens:
        assert token not in body, (
            f"the install note contains {token!r}, which "
            f"record_child_output_issue() collects into the ATTENTION block")

    assert "log_warn" not in body and "log_error" not in body, \
        "the note must be recorded via record_install_note, not a log_* helper"


def test_record_install_note_does_not_feed_the_issue_tracker():
    common = _read(os.path.join(REPO, "lib", "common.sh"))
    fn = common[common.index("record_install_note()"):]
    fn = fn[:fn.index("\n}")]
    assert "record_install_issue" not in fn, \
        "record_install_note must never call record_install_issue"
    assert "INSTALL_WARNINGS" not in fn and "INSTALL_ERRORS" not in fn, \
        "record_install_note must not touch the warning/error arrays"
    assert "[NOTE]" in fn, "notes should be tagged [NOTE] in the log file"


def test_the_upgrade_note_is_logged_at_info():
    """'warning' paints a yellow line for something that is not wrong;
    'error' increments error_count, and update_run_status() then demotes the
    completed run to failed."""
    src = _read(os.path.join(REPO, "modules", "backend", "services",
                             "upgrade", "timesketch.py"))
    start = src.index("def log_llm_provider_container_note")
    body = src[start:src.index("\ndef ", start + 10)]

    tree = ast.parse(body.replace("def log_llm_provider_container_note",
                                  "def f", 1))
    levels = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "log"):
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                levels.add(node.args[1].value)
    assert levels == {"info"}, \
        f"the upgrade note must log only at info level, found {sorted(levels)}"


def test_the_upgrade_note_is_wired_into_both_summaries():
    src = _read(os.path.join(REPO, "modules", "backend", "services",
                             "upgrade", "__init__.py"))
    assert src.count("log_llm_provider_container_note(results, logger=log)") == 2, (
        "the note must be emitted from both the offline/online summary and "
        "the Phase-2 resume twin")


def test_the_upgrade_refresh_lists_every_payload_file():
    """The apply side copies one file at a time; a payload file missing from
    that list simply never reaches an upgraded host."""
    src = _read(os.path.join(REPO, "modules", "backend", "services",
                             "upgrade", "intact.py"))
    assert "llm_providers" in src, \
        "intact.py never refreshes the llm_providers payload -- upgraded " \
        "hosts would get the bind mount with nothing behind it"

    block = src[src.index("for _rel in ("):]
    block = block[:block.index(")")]
    listed = set(re.findall(r"'([^']+)'", block))

    on_disk = {f for f in os.listdir(PROVIDER_DIR)
               if not f.startswith(".") and f != "__pycache__"}
    assert on_disk <= listed, (
        f"these payload files would never reach an upgraded host: "
        f"{sorted(on_disk - listed)}")


# --- the settings wiring -----------------------------------------------------


def _routes_module():
    import importlib.util
    path = os.path.join(REPO, "modules", "backend", "routes",
                        "timesketch_llm_routes.py")
    spec = importlib.util.spec_from_file_location("_tslr", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_ui_mode_generates_a_config_its_provider_can_read():
    routes = _routes_module()
    values = {
        "google_ai_model": "gemini-2.5-flash", "google_ai_key": "AIzaX",
        "ollama_url": "http://o:11434", "ollama_model": "llama3.1:8b",
        "openrouter_key": "sk-or-v1-x", "openrouter_model": "anthropic/claude-3.5-sonnet",
        "litellm_url": "http://l:4000", "litellm_model": "gpt-4o-mini",
        "litellm_key": "sk-lite",
    }
    for mode, (ts_provider, fields) in routes._TS_PROVIDERS.items():
        block = routes._provider_block(mode, values, "")
        namespace = {}
        exec(compile("CFG = {\n" + block + "\n}", "<gen>", "exec"), namespace)
        generated = namespace["CFG"]
        assert list(generated) == [ts_provider], generated
        assert set(generated[ts_provider]) == {f[0] for f in fields}, generated


def test_a_quote_in_an_operator_value_cannot_inject_python():
    """This is written verbatim into a .py file Timesketch imports as code."""
    routes = _routes_module()
    hostile = "http://x'}); import os; os.system('id'); ({'"
    block = routes._provider_block(
        "ollama", {"ollama_url": hostile, "ollama_model": "m"}, "")
    namespace = {}
    exec(compile("CFG = {\n" + block + "\n}", "<gen>", "exec"), namespace)
    assert namespace["CFG"]["ollama"]["server_url"] == hostile, \
        "the hostile value did not survive as an inert string"
    assert "os.system" not in str(namespace["CFG"]["ollama"]["model"])


def test_a_masked_key_is_never_written_through():
    """Saving the form GET handed you must not destroy the stored key."""
    routes = _routes_module()
    existing = (
        "LLM_PROVIDER_CONFIGS = {\n"
        "    'nl2q': {\n"
        "        'openrouter': {\n"
        "            'api_key': 'sk-or-v1-REAL-SECRET',\n"
        "            'model': 'x',\n"
        "        },\n"
        "    },\n"
        "}\n")
    block = routes._provider_block(
        "openrouter",
        {"openrouter_key": routes._mask_secret("sk-or-v1-REAL-SECRET"),
         "openrouter_model": "y"},
        existing)
    assert "sk-or-v1-REAL-SECRET" in block, \
        "the masked placeholder overwrote the real key"
    assert routes._API_KEY_MASK not in block, \
        "bullet characters were written into the config"


def test_the_selected_provider_is_recoverable_from_the_file():
    """GET has to return llm_mode or the UI shows the wrong provider on
    reload -- which is what happened while the mode was decorative."""
    routes = _routes_module()
    for mode, (ts_provider, _f) in routes._TS_PROVIDERS.items():
        content = "LLM_PROVIDER_CONFIGS = {\n    'nl2q': {\n        '%s': {\n" % ts_provider
        assert routes._detect_llm_mode(content) == mode, \
            f"{mode} did not round-trip through _detect_llm_mode"


def test_the_ui_offers_exactly_the_modes_the_backend_accepts():
    routes = _routes_module()
    html = _read(os.path.join(REPO, "modules", "nginx", "html", "partials",
                              "settings.html"))
    tab = html[html.index("<!-- Timesketch Tab -->"):html.index("<!-- Cloud Tab -->")]
    select = tab[tab.index("timesketch.llm_mode"):]
    select = select[:select.index("</select>")]
    offered = set(re.findall(r'<option value="([^"]+)"', select))
    assert offered == set(routes._TS_PROVIDERS), (
        f"the selector and the backend disagree.\n"
        f"  only in UI     : {sorted(offered - set(routes._TS_PROVIDERS))}\n"
        f"  only in backend: {sorted(set(routes._TS_PROVIDERS) - offered)}")


def test_every_provider_field_has_an_input_and_a_store_default():
    routes = _routes_module()
    html = _read(os.path.join(REPO, "modules", "nginx", "html", "partials",
                              "settings.html"))
    store = _read(os.path.join(REPO, "modules", "nginx", "html", "js",
                               "stores", "settings.js"))
    for mode, (_p, fields) in routes._TS_PROVIDERS.items():
        for _conf_key, ui_key, _secret in fields:
            assert f"timesketch.{ui_key}" in html, \
                f"{mode}: no input bound to {ui_key}"
            assert f"{ui_key}:" in store, \
                f"{mode}: {ui_key} has no default in the settings store"


def _ts_tab():
    html = _read(os.path.join(REPO, "modules", "nginx", "html", "partials",
                              "settings.html"))
    return html[html.index("<!-- Timesketch Tab -->"):html.index("<!-- Cloud Tab -->")]


def test_no_model_list_is_hardcoded():
    """Every hardcoded list goes stale the moment a vendor ships a model.

    The Google field shipped with gemini-2.5-flash / 2.5-pro / 1.5-pro baked
    into the markup; by the time anyone looked, 1.5-pro was retired and the
    live catalog had 32 entries including a whole generation the UI could not
    offer. Model names belong in a catalog, not in HTML.
    """
    tab = _ts_tab()
    for stale in ("gemini-1.5-pro", "gemini-2.5-pro", "gemini-2.5-flash"):
        assert f'<option value="{stale}"' not in tab, (
            f"{stale} is hardcoded as an <option> — use the live catalog "
            f"(/api/config/gemini/models) instead")


def test_every_model_field_is_catalog_or_server_backed():
    """A hand-typed id is how you end up pinned to something the vendor
    renamed and get a 404 at request time.

    LiteLLM is the deliberate exception: its model names are whatever the
    operator registered in their own proxy config, so there is nothing to
    enumerate.
    """
    tab = _ts_tab()
    cases = [
        ("google",     "llm_mode === 'ollama'",     "/api/config/gemini/models",
         "timesketch.google_ai_model = model.id"),
        ("openrouter", "llm_mode === 'litellm'",    "/api/config/openrouter/models",
         "timesketch.openrouter_model = model.id"),
    ]
    for label, next_marker, endpoint, writeback in cases:
        block = tab[tab.index(f"llm_mode === '{label}'") if label != "google"
                    else tab.index("Google AI Studio Configuration"):]
        block = block[:block.index(next_marker)]
        assert endpoint in block, f"{label}: model field is not catalog-backed"
        assert writeback in block, \
            f"{label}: picking a catalog entry must write the id back to the store"

    # Ollama can't use a static catalog — it asks the operator's own server.
    ollama = tab[tab.index("llm_mode === 'ollama'"):tab.index("llm_mode === 'openrouter'")]
    assert "/api/config/ollama/models" in ollama, \
        "the Ollama model field should be able to list what that server has"


def test_no_x_data_block_can_break_out_of_its_attribute():
    """Each block lives inside a double-quoted attribute; one double quote
    terminates it and dumps the script onto the page as visible text."""
    for data_block in re.findall(r'x-data="([^"]*)"', _ts_tab(), re.DOTALL):
        assert '"' not in data_block, \
            "a double quote inside an x-data attribute breaks out of it"


def test_the_timesketch_save_seeds_the_openrouter_catalog():
    """An operator who never opens the Agentic tab must still get a populated
    model list, so the save path refreshes the shared catalog the same way
    saveAgentic() does."""
    store = _read(os.path.join(REPO, "modules", "nginx", "html", "js",
                               "stores", "settings.js"))
    save = store[store.index("async saveTimesketch()"):]
    save = save[:save.index("\n        },")]
    assert "refresh-openrouter-models" in save, \
        "saveTimesketch does not refresh the OpenRouter catalog"
    assert "llm-catalog-refreshed" in save, \
        "saveTimesketch does not tell the combobox to re-query"


def test_all_four_timesketch_containers_are_restarted_on_save():
    """web_v3 reads the same timesketch.conf as the others and was silently
    missing every settings change."""
    src = _read(os.path.join(REPO, "modules", "backend", "routes",
                             "timesketch_llm_routes.py"))
    for container in ("intact_timesketch_web", "intact_timesketch_worker",
                      "intact_timesketch_web_legacy", "intact_timesketch_web_v3"):
        assert container in src, f"{container} is not restarted on a settings save"


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
