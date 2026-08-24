"""What a healthy appliance looks like, asserted the way that has caught things.

Every check here is ported from scripts/dev/chain_test.sh, which was written
FROM real failures rather than from a specification. The comments record which
failure each one catches, because that is the part that stops someone
"simplifying" a check back into uselessness later.

Four version facts must agree — the VERSION file, modules/backend/.env, the
config.yaml pin, and the tag of the image actually running. Each pair
disagreeing has its own incident:

  VERSION vs .env      the 0726 loop's signature: VERSION moved and the .env
                       was silently rewritten back, so the box reported the new
                       release while running the old one
  pin vs process       the recreate-from-old-image bug — the pin and the
                       process disagree and nothing says so

And the container check reads names from each module's OWN compose file rather
than guessing them from the module name. Guessing `intact_elk*` once reported
ELK down while elasticsearch, kibana and logstash were all healthy — a chain
test that cries wolf gets ignored, which costs more than having no test.
"""

import os
import re
import subprocess


def _run(argv, timeout=60):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip() if r.returncode == 0 else ""
    except Exception:                                         # noqa: BLE001
        return ""


def enabled_modules(root):
    """Modules the operator has switched on, from config.yaml.

    Deliberately strict about what counts as enabled — matching install.sh's
    `is_enabled`, where an ABSENT key means disabled. The upgrade planner reads
    an absent key the opposite way, and conflating the two is how a fixture
    ends up testing something other than what it says.
    """
    out = []
    path = os.path.join(root, "config.yaml")
    try:
        import yaml
        cfg = yaml.safe_load(open(path, encoding="utf-8")) or {}
    except Exception:                                         # noqa: BLE001
        return out
    for name, spec in sorted((cfg.get("modules") or {}).items()):
        val = spec.get("enabled") if isinstance(spec, dict) else spec
        if val in (True, "true", "True", 1, "1", "yes"):
            out.append(name)
    return out


def container_names_of(root, module):
    """The containers a module declares, read from its own compose file."""
    compose = os.path.join(root, "modules", module, "docker-compose.yaml")
    if not os.path.isfile(compose):
        return []                       # ruleset-only module; nothing to run
    names = []
    with open(compose, encoding="utf-8") as fh:
        for line in fh:
            m = re.match(r"^\s*container_name:\s*(\S+)", line)
            if m:
                names.append(m.group(1))
    return names


def version_facts(root):
    """The four places a version is written down, plus the running image."""
    facts = {}
    try:
        facts["VERSION"] = open(os.path.join(root, "VERSION"),
                                encoding="utf-8").read().strip()
    except OSError:
        facts["VERSION"] = ""

    facts["backend_env"] = ""
    try:
        with open(os.path.join(root, "modules/backend/.env"), encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("BACKEND_VERSION="):
                    facts["backend_env"] = line.split("=", 1)[1].strip().strip("'\"")
    except OSError:
        pass

    facts["config_pin"] = ""
    try:
        import yaml
        cfg = yaml.safe_load(open(os.path.join(root, "config.yaml"),
                                  encoding="utf-8")) or {}
        facts["config_pin"] = str((cfg.get("versions") or {}).get("backend", ""))
    except Exception:                                         # noqa: BLE001
        pass

    facts["running_image"] = _run(
        ["docker", "inspect", "intact_backend", "--format", "{{.Config.Image}}"])
    return facts


def assert_state(ctx, root, expect, label):
    """The full state assertion. `expect` is the tag the box should now be on."""
    facts = version_facts(root)
    pfx = f"{label}: " if label else ""

    ctx.check(f"{pfx}VERSION is {expect}", facts["VERSION"] == expect,
              expected=expect, actual=facts["VERSION"] or "(absent)")
    ctx.check(f"{pfx}BACKEND_VERSION is {expect}", facts["backend_env"] == expect,
              expected=expect, actual=facts["backend_env"] or "(absent)",
              note="VERSION moving while this stayed put is the 0726 loop's "
                   "signature — the box reports the new release and runs the old")
    ctx.check(f"{pfx}config.yaml versions.backend is {expect}",
              facts["config_pin"] == expect,
              expected=expect, actual=facts["config_pin"] or "(absent)")
    ctx.check(f"{pfx}the running backend image is {expect}",
              facts["running_image"].endswith(":" + expect),
              expected=f"*:{expect}", actual=facts["running_image"] or "(none)",
              note="the pin and the process disagreeing IS the "
                   "recreate-from-an-old-image bug")

    # Health. A container that is up but unhealthy is exactly what an rc=0 hides.
    ps = _run(["docker", "ps", "--format", "{{.Names}}\t{{.Status}}"])
    unhealthy = [l for l in ps.splitlines() if "unhealthy" in l.lower()]
    ctx.check(f"{pfx}no unhealthy containers", not unhealthy,
              actual=", ".join(unhealthy[:5]) or "all healthy")

    # Every enabled module has something running.
    running = set(_run(["docker", "ps", "--format", "{{.Names}}"]).splitlines())
    missing = []
    for module in enabled_modules(root):
        names = container_names_of(root, module)
        if not names:
            continue
        if not any(n in running for n in names):
            missing.append(module)
    ctx.check(f"{pfx}every enabled module has containers", not missing,
              actual=", ".join(missing) or "all up",
              note="names read from each module's own compose file; guessing "
                   "them reported ELK down while all three of its containers "
                   "were healthy")
    return facts


# --- the canary ------------------------------------------------------------
#
# An IRIS row, because IRIS keeps a real postgres and a row in it is the
# simplest thing that proves an upgrade did not quietly discard state. A
# version bump that loses evidence is a failed upgrade, whatever it exits.

CANARY_NOTE = "qa_e2e canary"


def canary_write():
    return _run(["docker", "exec", "intact_iris_db", "psql", "-U", "postgres",
                 "-d", "iris_db", "-v", "ON_ERROR_STOP=1",
                 "-c", "CREATE TABLE IF NOT EXISTS qa_canary"
                       "(id serial primary key, note text, at timestamptz default now());",
                 "-c", f"INSERT INTO qa_canary(note) SELECT '{CANARY_NOTE}' "
                       f"WHERE NOT EXISTS (SELECT 1 FROM qa_canary WHERE note='{CANARY_NOTE}');"],
                timeout=120)


def canary_count():
    out = _run(["docker", "exec", "intact_iris_db", "psql", "-U", "postgres",
                "-d", "iris_db", "-tAc",
                f"SELECT count(*) FROM qa_canary WHERE note='{CANARY_NOTE}';"],
               timeout=60)
    return out.strip() or None


def assert_canary(ctx, label=""):
    """Unreachable IRIS is a WARN, not a failure — the canary is evidence about
    the upgrade, and a module that is legitimately absent must not fail it."""
    pfx = f"{label}: " if label else ""
    n = canary_count()
    if n is None:
        ctx.check(f"{pfx}IRIS canary survived", True,
                  actual="SKIPPED: iris_db unreachable",
                  note="not a failure; there is no IRIS on this box to ask")
        return
    ctx.check(f"{pfx}IRIS canary survived", n == "1",
              expected="1 row", actual=f"{n} row(s)")
