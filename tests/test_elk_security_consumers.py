"""Turning on Elasticsearch security has three consumers, not one.

WHAT HAPPENED
-------------
The 20260803 ELK release set `xpack.security.enabled=true`. Elasticsearch then
rejects anonymous requests from everyone. The release provisioned exactly one
consumer:

    Kibana    kibana_system, created by the new `setup` service   OK
    Logstash  no credentials in its pipeline output               401, 24 restarts
    backend   ELASTICSEARCH_USER empty, password unset            401 on every query

Observed on the upgraded box:

    [ELASTICSEARCH] Failed to get workflow runs: AuthenticationException(401,
      'security_exception', 'missing authentication credentials for REST
       request [/intact_workflow_runs/_search]')

repeating indefinitely, while `docker ps` showed Elasticsearch healthy, Kibana
healthy, elk_setup exited 0, backend healthy, and the upgrade reported success.
Every summary signal was green and workflow history was silently unreachable.

NEVER ROTATE
------------
Elasticsearch fixes the `elastic` password at initdb. Generating a fresh one on
an existing cluster locks the platform out of its own data -- strictly worse
than the bug being fixed. An existing password is reused as-is; only a
genuinely absent one is seeded, and then the operator is told to change it.

Run: docker exec intact_backend python /app/workdir/tests/test_elk_security_consumers.py
"""

import os
import re
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import elk  # noqa: E402

REPO = os.environ.get("INTACT_PATH", "/app/workdir")

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


def _box(elk_env_lines, backend_env_lines="ELASTICSEARCH_HOST=elasticsearch\n"):
    d = tempfile.mkdtemp(prefix="elkcred_")
    os.makedirs(os.path.join(d, "modules", "elk"))
    os.makedirs(os.path.join(d, "modules", "backend"))
    with open(os.path.join(d, "modules/elk/.env"), "w") as f:
        f.write(elk_env_lines)
    with open(os.path.join(d, "modules/backend/.env"), "w") as f:
        f.write(backend_env_lines)
    return d


def _run(box):
    out = []
    prev = elk.WORKDIR
    elk.WORKDIR = box
    try:
        res = elk.ensure_elk_credentials(
            logger=lambda m, l="info": out.append((m, l)))
    finally:
        elk.WORKDIR = prev
    return res, out


def _env(path):
    vals = {}
    for line in open(path):
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    return vals


def test_an_existing_password_is_never_rotated():
    """The critical property. Elasticsearch fixes the elastic password at
    initdb, so a rotation locks the platform out of its own cluster."""
    box = _box("ELASTIC_USER=elastic\nELASTIC_PASSWORD=AlreadySetOnThisBox\n")
    res, out = _run(box)
    after = _env(os.path.join(box, "modules/elk/.env"))
    check("the existing password survives",
          after.get("ELASTIC_PASSWORD") == "AlreadySetOnThisBox",
          f"became {after.get('ELASTIC_PASSWORD')!r}")
    check("it is not reported as seeded", res["seeded"] is False, str(res))
    check("and it says it reused them",
          any("reusing the existing" in m for m, _ in out), str(out))


def test_a_missing_password_is_seeded_and_loudly_flagged():
    """First box onto security. A default is better than a broken stack, but
    only if the operator is told -- silently defaulting a credential is how you
    ship an appliance with a known password."""
    box = _box("ELASTIC_USER=elastic\n")
    res, out = _run(box)
    body = "\n".join(m for m, _ in out)
    levels = [l for _, l in out]
    check("it is reported as seeded", res["seeded"] is True, str(res))
    check("the warning is at warning level", "warning" in levels, str(levels))
    check("it says the credentials are DEFAULT",
          "DEFAULT" in body, body)
    check("it says exactly how to change them",
          "ELASTIC_PASSWORD" in body and "modules/elk/.env" in body, body)


def test_the_backend_receives_the_same_credentials():
    """The consumer that was silently broken. Same password or it 401s."""
    box = _box("ELASTIC_USER=elastic\nELASTIC_PASSWORD=SharedSecretValue\n")
    _run(box)
    be = _env(os.path.join(box, "modules/backend/.env"))
    check("backend gets the user", be.get("ELASTICSEARCH_USER") == "elastic",
          str(be))
    check("backend gets the same password",
          be.get("ELASTICSEARCH_PASSWORD") == "SharedSecretValue", str(be))


def test_it_is_idempotent():
    """Runs on every upgrade. A second run must change nothing."""
    box = _box("ELASTIC_USER=elastic\nELASTIC_PASSWORD=StableValue123\n")
    _run(box)
    first = open(os.path.join(box, "modules/backend/.env")).read()
    res2, _ = _run(box)
    second = open(os.path.join(box, "modules/backend/.env")).read()
    check("a second run changes nothing", first == second, "the file moved")
    check("and reports nothing propagated", not res2["propagated"], str(res2))


def test_kibana_gets_a_password_too():
    """Kibana's service account is what the setup service configures; leaving
    it blank puts Kibana in the same 401 hole as the others."""
    box = _box("ELASTIC_USER=elastic\nELASTIC_PASSWORD=Value999\n")
    _run(box)
    after = _env(os.path.join(box, "modules/elk/.env"))
    check("KIBANA_PASSWORD is set", bool(after.get("KIBANA_PASSWORD")), str(after))


def test_an_existing_kibana_password_is_kept():
    box = _box("ELASTIC_USER=elastic\nELASTIC_PASSWORD=a\nKIBANA_PASSWORD=KeepMe\n")
    _run(box)
    after = _env(os.path.join(box, "modules/elk/.env"))
    check("KIBANA_PASSWORD is not overwritten",
          after.get("KIBANA_PASSWORD") == "KeepMe", str(after))


# ------------------------------------------------- the consumers in the repo

def test_logstash_output_authenticates():
    """The crash loop. Logstash's pipeline had no credentials at all."""
    p = os.path.join(REPO, "modules/elk/config/pipeline/main.conf")
    body = open(p).read()
    out = body[body.find("output"):]
    check("logstash sends a user", "user =>" in out, out[:300])
    check("logstash sends a password", "password =>" in out, out[:300])


def test_the_backend_falls_back_to_the_elk_env():
    """The backend restarts BEFORE the ELK module runs, so an env var written
    during the ELK upgrade reaches it on a restart that never comes. Reading
    modules/elk/.env is what lets the running process recover in place."""
    src = open(os.path.join(REPO, "modules/backend/config.py")).read()
    src = re.sub(r'"""[\s\S]*?"""', '', src)
    src = "\n".join(l.split('#')[0] for l in src.splitlines())
    check("config.py reads the elk env as a fallback",
          "_elk_env_credential" in src and "ELASTIC_PASSWORD" in src,
          "no fallback wired")
    check("the environment still wins",
          src.index("os.environ.get('ELASTICSEARCH_PASSWORD'")
          < src.index("_elk_env_credential('ELASTIC_PASSWORD')"),
          "the file would override an explicit environment variable")


def test_security_is_actually_on_so_this_all_matters():
    """If a later release turns security back off, these tests should stop
    being load-bearing rather than silently pass for the wrong reason."""
    compose = open(os.path.join(REPO, "modules/elk/docker-compose.yaml")).read()
    check("xpack.security.enabled=true is still set",
          "xpack.security.enabled=true" in compose,
          "security is off -- revisit whether these consumers still need creds")


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)
