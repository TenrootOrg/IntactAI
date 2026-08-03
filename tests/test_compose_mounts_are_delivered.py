"""A compose file may not reference a host path nobody delivers.

WHAT WENT WRONG
---------------
The ELK release added a `setup` service:

    volumes:
      - ./config/setup-kibana-user.sh:/usr/local/bin/setup-kibana-user.sh:ro
    entrypoint: ["/bin/bash", "/usr/local/bin/setup-kibana-user.sh"]

refresh_module_compose_file() shipped that compose file to boxes installed
before it -- correctly; without it a structural compose change stays frozen on
that box forever. But it copies the compose file and nothing else, deliberately,
because the module directory also holds per-install state a mirror would clobber.

So the compose file arrived and the script did not. Docker does not error on a
bind mount whose host path is missing: it creates an empty DIRECTORY there.
`/bin/bash <a directory>` exits 126, and the operator saw

    Container intact_elk_setup  service "setup" didn't complete successfully: exit 126

with nothing naming the file. Confirmed on the failing box:

    setup-kibana-user.sh in intact-20260726 : absent
    setup-kibana-user.sh in development     : present, mode 100755

THE INVARIANT THIS ENFORCES
---------------------------
Every relative bind source in every module compose file is either

  (a) shipped code, present in the repo -- the upgrade must deliver it; or
  (b) install-generated, absent from the repo and listed in
      compose_assets.INSTALL_GENERATED with the step that creates it.

There is no third case. Adding a mount to any module now forces the author to
put it in one bucket or the other, at review time, instead of at a customer's
upgrade. This test run against the ELK commit fails on
modules/elk/config/setup-kibana-user.sh -- see
test_it_would_have_caught_the_elk_regression, which reproduces that tree state
rather than asserting the claim.

Run: docker exec intact_backend python /app/workdir/tests/test_compose_mounts_are_delivered.py
"""

import os
import shutil
import sys
import tempfile

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import compose_assets as ca  # noqa: E402

REPO = os.environ.get("INTACT_PATH", "/app/workdir")

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


def _module_composes():
    mroot = os.path.join(REPO, "modules")
    for m in sorted(os.listdir(mroot)):
        p = os.path.join(mroot, m, "docker-compose.yaml")
        if os.path.isfile(p):
            yield m, p


def _all_refs():
    for m, p in _module_composes():
        for ref in ca.iter_bind_sources(p, m):
            yield m, ref


# ---------------------------------------------------------------- the invariant

def test_every_bind_source_is_shipped_or_allowlisted():
    """The gate. A mount pointing at a path that is neither in the repo nor
    declared install-generated is the ELK bug, waiting for someone to upgrade."""
    unexplained = []
    for m, ref in _all_refs():
        if os.path.exists(os.path.join(REPO, ref.repo_path)):
            continue
        if ref.repo_path in ca.INSTALL_GENERATED:
            continue
        unexplained.append(
            f"{m}/{ref.service} mounts {ref.repo_path} -> {ref.target or '(env_file)'}")
    check("every bind source is shipped or allowlisted", not unexplained,
          "not in the repo and not in INSTALL_GENERATED: " + "; ".join(unexplained))


def test_executed_mounts_are_always_shipped():
    """A mount the service EXECUTES can never be install-generated -- there is
    no appliance step that writes a program. It must be in the repo, full stop.
    This is the exit-126 class, isolated."""
    missing = []
    for m, ref in _all_refs():
        if ref.executed and not os.path.exists(os.path.join(REPO, ref.repo_path)):
            missing.append(f"{m}/{ref.service} runs {ref.target} from {ref.repo_path}")
    check("executed mounts are shipped", not missing,
          "executed but absent from the repo: " + "; ".join(missing))


def test_the_allowlist_has_no_stale_entries():
    """An allowlist that outlives its mount stops describing the system and
    starts hiding the next one."""
    referenced = {ref.repo_path for _, ref in _all_refs()}
    stale = sorted(set(ca.INSTALL_GENERATED) - referenced)
    check("no stale INSTALL_GENERATED entries", not stale,
          "listed but no longer mounted by any compose file: " + ", ".join(stale))


def test_every_allowlist_entry_says_who_creates_it():
    """The reason string is the whole point -- 'it's fine, something makes it'
    is what produced the missing timesketch postgres.env."""
    thin = [k for k, v in ca.INSTALL_GENERATED.items() if len(v.split()) < 3]
    check("allowlist reasons name a creating step", not thin,
          f"reasons too thin to be useful: {thin}")


def test_the_elk_setup_script_is_present_and_executable():
    """The specific file whose absence produced exit 126. Mounted read-only and
    exec'd by /bin/bash, so it needs the execute bit -- and `chmod +x` masked by
    umask has shipped a non-executable script from this repo before."""
    p = os.path.join(REPO, "modules/elk/config/setup-kibana-user.sh")
    check("elk setup script exists", os.path.isfile(p), f"{p} missing")
    if os.path.isfile(p):
        mode = os.stat(p).st_mode & 0o777
        check("elk setup script is executable", mode & 0o111,
              f"mode {oct(mode)} has no execute bit")


# ------------------------------------------------------------------ the parser

def test_it_reads_short_and_long_volume_syntax():
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write(
                "services:\n"
                "  a:\n"
                "    volumes:\n"
                "      - ./config/x.sh:/x.sh:ro\n"
                "      - type: bind\n"
                "        source: ./config/y.conf\n"
                "        target: /y.conf\n")
        refs = ca.iter_bind_sources(p, "m")
        got = {r.repo_path for r in refs}
        check("reads short and long volume syntax",
              got == {"modules/m/config/x.sh", "modules/m/config/y.conf"}, str(got))


def test_it_ignores_what_it_cannot_own():
    """Absolute host paths belong to the host, named volumes to Docker, and a
    ${VAR} source cannot be resolved without the runtime environment. Treating
    any of them as a missing asset would produce noise that trains people to
    ignore the real finding."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write(
                "services:\n"
                "  a:\n"
                "    volumes:\n"
                "      - /var/run/docker.sock:/var/run/docker.sock:rw\n"
                "      - esdata:/usr/share/elasticsearch/data\n"
                "      - ${SOME_DIR}/z:/z\n"
                "      - ./real:/real\n")
        got = {r.repo_path for r in ca.iter_bind_sources(p, "m")}
        check("ignores absolute paths, named volumes and ${VAR}",
              got == {"modules/m/real"}, str(got))


def test_it_resolves_parent_relative_sources():
    """`../nginx/ssl/...` is how five modules reach the shared cert. Getting the
    normalisation wrong would silently exempt them from the gate."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write("services:\n  a:\n    volumes:\n"
                    "      - ../nginx/ssl/nginx-cert.crt:/certs/cert.crt:ro\n"
                    "      - ../../data:/app/data\n")
        got = {r.repo_path for r in ca.iter_bind_sources(p, "elk")}
        check("resolves ../ and ../../ sources",
              got == {"modules/nginx/ssl/nginx-cert.crt", "data"}, str(got))


def test_it_reads_env_file_too():
    """timesketch's postgres.env and portainer's agent.env are env_file entries,
    not volumes. Same failure class, different key."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write("services:\n  a:\n    env_file:\n      - ./secrets/pg.env\n")
        got = {r.repo_path for r in ca.iter_bind_sources(p, "m")}
        check("reads env_file entries", got == {"modules/m/secrets/pg.env"}, str(got))


def test_it_marks_executed_targets():
    """`executed` is what separates 'will exit 126' from 'probably fine'."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write(
                "services:\n"
                "  setup:\n"
                "    volumes:\n"
                "      - ./config/run.sh:/usr/local/bin/run.sh:ro\n"
                "      - ./config/data.yml:/data.yml:ro\n"
                '    entrypoint: ["/bin/bash", "/usr/local/bin/run.sh"]\n')
        refs = {r.target: r.executed for r in ca.iter_bind_sources(p, "m")}
        check("marks the entrypoint's mount as executed",
              refs.get("/usr/local/bin/run.sh") is True, str(refs))
        check("does not mark a plain data mount as executed",
              refs.get("/data.yml") is False, str(refs))


def test_an_option_value_is_not_a_program():
    """Portainer's real command line. Every one of these paths is an option
    VALUE, and all three are legitimately created by install.sh later. Counting
    them as executed aborted every Portainer upgrade on the first run of this
    code -- the gate has to be precise or it gets switched off."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write(
                "services:\n"
                "  portainer:\n"
                "    volumes:\n"
                "      - ../nginx/ssl/nginx-cert.crt:/certs/cert.pem:ro\n"
                "      - ./secrets/admin_password:/run/secrets/pw:ro\n"
                "    command: >-\n"
                "      -H tcp://agent:9001 --tlscert /certs/cert.pem\n"
                "      --admin-password-file /run/secrets/pw\n")
        refs = ca.iter_bind_sources(p, "portainer")
        check("option values are not executed",
              not any(r.executed for r in refs),
              str([(r.target, r.executed) for r in refs]))


def test_an_interpreter_entrypoint_finds_the_program_in_command():
    """IRIS splits it across both keys: `entrypoint: /bin/bash` +
    `command: [/postgres_start_with_secrets.sh]`. Same exit-126 exposure as
    ELK's single-key form, and it must resolve identically."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write(
                "services:\n"
                "  db:\n"
                "    volumes:\n"
                "      - ./scripts/postgres_start_with_secrets.sh:"
                "/postgres_start_with_secrets.sh:ro\n"
                "    entrypoint: /bin/bash\n"
                "    command:\n"
                "      - /postgres_start_with_secrets.sh\n")
        refs = ca.iter_bind_sources(p, "iris")
        check("interpreter entrypoint + command program is executed",
              refs and refs[0].executed, str(refs))


def test_it_marks_string_command_targets():
    """`command: /x.sh --flag` is as fatal as the list form."""
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "docker-compose.yaml")
        with open(p, "w") as f:
            f.write("services:\n  a:\n    volumes:\n"
                    "      - ./s.sh:/s.sh:ro\n"
                    "    command: /s.sh --once\n")
        refs = ca.iter_bind_sources(p, "m")
        check("marks string-form command targets", refs[0].executed, str(refs))


# ------------------------------------------------- the regression, reproduced

def test_it_would_have_caught_the_elk_regression():
    """Fault injection rather than assertion. Build the exact tree state that
    shipped -- new compose file, script absent -- and require a fatal finding
    naming the file."""
    with tempfile.TemporaryDirectory() as d:
        mdir = os.path.join(d, "modules", "elk")
        os.makedirs(os.path.join(mdir, "config"))
        real = os.path.join(REPO, "modules/elk/docker-compose.yaml")
        shutil.copy2(real, os.path.join(mdir, "docker-compose.yaml"))
        # config/ exists but the script does not -- exactly the shipped state.
        orig, ca.WORKDIR = ca.WORKDIR, d
        try:
            fatal = ca.verify_referenced_assets("elk", logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        check("the elk regression is caught",
              any("setup-kibana-user.sh" in f for f in fatal),
              f"no fatal finding named the script: {fatal}")
        check("the finding explains the empty-directory mechanism",
              any("DIRECTORY" in f and "126" in f for f in fatal),
              f"finding does not explain the failure: {fatal}")


def test_delivery_fills_the_gap_and_preserves_the_execute_bit():
    """A delivered script that is not executable fails exactly as loudly as a
    missing one."""
    with tempfile.TemporaryDirectory() as d:
        src_root = os.path.join(d, "src")
        appliance = os.path.join(d, "box")
        for root in (src_root, appliance):
            os.makedirs(os.path.join(root, "modules", "elk", "config"))
        shutil.copy2(os.path.join(REPO, "modules/elk/docker-compose.yaml"),
                     os.path.join(appliance, "modules/elk/docker-compose.yaml"))
        script = os.path.join(src_root, "modules/elk/config/setup-kibana-user.sh")
        with open(script, "w") as f:
            f.write("#!/bin/bash\necho hi\n")
        os.chmod(script, 0o755)
        # logstash.yml too, so the run covers more than one mount
        with open(os.path.join(src_root, "modules/elk/config/logstash.yml"), "w") as f:
            f.write("http.host: 0.0.0.0\n")

        orig, ca.WORKDIR = ca.WORKDIR, appliance
        try:
            n = ca.deliver_referenced_assets("elk", src_root,
                                             logger=lambda *a, **k: None)
            landed = os.path.join(appliance, "modules/elk/config/setup-kibana-user.sh")
            check("the missing script is delivered", os.path.isfile(landed),
                  f"not delivered (delivered={n})")
            if os.path.isfile(landed):
                check("the delivered script keeps its execute bit",
                      os.stat(landed).st_mode & 0o111,
                      f"mode {oct(os.stat(landed).st_mode & 0o777)}")
            fatal = ca.verify_referenced_assets("elk", logger=lambda *a, **k: None)
            check("delivery clears the fatal finding", not fatal, str(fatal))
        finally:
            ca.WORKDIR = orig


def test_delivery_never_overwrites_operator_state():
    """timesketch mounts its whole ./config directory and the backend writes LLM
    settings into it. Fill-the-gap is the only safe rule; an overwrite here
    would destroy live configuration to deliver a default."""
    with tempfile.TemporaryDirectory() as d:
        src_root = os.path.join(d, "src")
        appliance = os.path.join(d, "box")
        for root in (src_root, appliance):
            os.makedirs(os.path.join(root, "modules", "elk", "config"))
        shutil.copy2(os.path.join(REPO, "modules/elk/docker-compose.yaml"),
                     os.path.join(appliance, "modules/elk/docker-compose.yaml"))
        with open(os.path.join(src_root, "modules/elk/config/logstash.yml"), "w") as f:
            f.write("SHIPPED DEFAULT\n")
        live = os.path.join(appliance, "modules/elk/config/logstash.yml")
        with open(live, "w") as f:
            f.write("OPERATOR EDIT\n")

        orig, ca.WORKDIR = ca.WORKDIR, appliance
        try:
            ca.deliver_referenced_assets("elk", src_root, logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        with open(live) as f:
            check("an existing mounted file is never overwritten",
                  f.read().strip() == "OPERATOR EDIT", "the shipped default won")


def test_delivery_is_a_noop_without_a_source_tree():
    """An incomplete package must not be able to delete or blank a working
    file -- the same property refresh_module_compose_file guarantees."""
    with tempfile.TemporaryDirectory() as d:
        appliance = os.path.join(d, "box")
        os.makedirs(os.path.join(appliance, "modules", "elk", "config"))
        shutil.copy2(os.path.join(REPO, "modules/elk/docker-compose.yaml"),
                     os.path.join(appliance, "modules/elk/docker-compose.yaml"))
        keep = os.path.join(appliance, "modules/elk/config/logstash.yml")
        with open(keep, "w") as f:
            f.write("KEEP ME\n")
        orig, ca.WORKDIR = ca.WORKDIR, appliance
        try:
            n = ca.deliver_referenced_assets("elk", os.path.join(d, "nonexistent"),
                                             logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        check("empty source tree delivers nothing", n == 0, f"delivered {n}")
        with open(keep) as f:
            check("empty source tree destroys nothing", f.read().strip() == "KEEP ME", "")


# ------------------------------------------------------------- self-repair

def _elk_box(tmpdir):
    """An appliance directory carrying the new ELK compose file."""
    os.makedirs(os.path.join(tmpdir, "modules", "elk", "config"), exist_ok=True)
    shutil.copy2(os.path.join(REPO, "modules/elk/docker-compose.yaml"),
                 os.path.join(tmpdir, "modules/elk/docker-compose.yaml"))
    return tmpdir


def test_it_repairs_the_empty_directory_docker_left_behind():
    """The damage is self-perpetuating without this.

    A box that already hit the bug has Docker's empty directory sitting exactly
    where the script belongs. A plain exists() check calls that 'already
    delivered' and skips it -- so the box stays broken through every future
    upgrade, and the repair never reaches the population that needs it."""
    with tempfile.TemporaryDirectory() as d:
        src_root, box = os.path.join(d, "src"), _elk_box(os.path.join(d, "box"))
        os.makedirs(os.path.join(src_root, "modules", "elk", "config"))
        real = os.path.join(src_root, "modules/elk/config/setup-kibana-user.sh")
        with open(real, "w") as f:
            f.write("#!/bin/bash\necho ok\n")
        os.chmod(real, 0o755)
        # Docker's leftover: a directory where the file belongs.
        broken = os.path.join(box, "modules/elk/config/setup-kibana-user.sh")
        os.makedirs(broken)

        orig, ca.WORKDIR = ca.WORKDIR, box
        try:
            ca.deliver_referenced_assets("elk", src_root, logger=lambda *a, **k: None)
            fatal = ca.verify_referenced_assets("elk", logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        check("the empty directory is replaced by the real file",
              os.path.isfile(broken), "still a directory" if os.path.isdir(broken)
              else "missing entirely")
        check("the repaired file is executable",
              os.path.isfile(broken) and os.stat(broken).st_mode & 0o111, "")
        check("nothing fatal remains", not fatal, str(fatal))


def test_it_refuses_to_delete_a_directory_with_contents():
    """Only Docker's EMPTY placeholder is disposable. Anything with contents is
    real data, and no upgrade gets to delete that to make a mount fit."""
    with tempfile.TemporaryDirectory() as d:
        src_root, box = os.path.join(d, "src"), _elk_box(os.path.join(d, "box"))
        os.makedirs(os.path.join(src_root, "modules", "elk", "config"))
        with open(os.path.join(src_root, "modules/elk/config/setup-kibana-user.sh"),
                  "w") as f:
            f.write("#!/bin/bash\n")
        occupied = os.path.join(box, "modules/elk/config/setup-kibana-user.sh")
        os.makedirs(occupied)
        with open(os.path.join(occupied, "someones_data.txt"), "w") as f:
            f.write("do not delete me\n")

        orig, ca.WORKDIR = ca.WORKDIR, box
        try:
            ca.deliver_referenced_assets("elk", src_root, logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        check("a non-empty directory is left alone",
              os.path.isfile(os.path.join(occupied, "someones_data.txt")),
              "the upgrade deleted operator data")


def test_it_repairs_a_delivered_script_that_lost_its_execute_bit():
    """`chmod +x` (symbolic, no 'who') is filtered by the process umask;
    `chmod 755` is not. This repo has shipped a non-executable script through
    exactly that route, and the container symptom is identical to the file
    being absent: exit 126. The correct mode is not a judgement call, so repair
    it rather than making an operator diagnose it."""
    with tempfile.TemporaryDirectory() as d:
        box = _elk_box(os.path.join(d, "box"))
        script = os.path.join(box, "modules/elk/config/setup-kibana-user.sh")
        with open(script, "w") as f:
            f.write("#!/bin/bash\n")
        os.chmod(script, 0o644)
        # the other mounts, so the run reaches the script
        with open(os.path.join(box, "modules/elk/config/logstash.yml"), "w") as f:
            f.write("http.host: 0.0.0.0\n")

        orig, ca.WORKDIR = ca.WORKDIR, box
        try:
            fatal = ca.verify_referenced_assets("elk", logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        check("the execute bit is restored",
              os.stat(script).st_mode & 0o111,
              f"mode {oct(os.stat(script).st_mode & 0o777)}")
        check("and it is no longer fatal", not fatal, str(fatal))


def test_a_plain_data_mount_is_not_made_executable():
    """Repair is scoped to programs. Silently chmod-ing every mounted file to
    755 would be a permission change nobody asked for."""
    with tempfile.TemporaryDirectory() as d:
        box = _elk_box(os.path.join(d, "box"))
        with open(os.path.join(box, "modules/elk/config/setup-kibana-user.sh"),
                  "w") as f:
            f.write("#!/bin/bash\n")
        os.chmod(os.path.join(box, "modules/elk/config/setup-kibana-user.sh"), 0o755)
        data = os.path.join(box, "modules/elk/config/logstash.yml")
        with open(data, "w") as f:
            f.write("http.host: 0.0.0.0\n")
        os.chmod(data, 0o644)

        orig, ca.WORKDIR = ca.WORKDIR, box
        try:
            ca.verify_referenced_assets("elk", logger=lambda *a, **k: None)
        finally:
            ca.WORKDIR = orig
        check("a data mount keeps its mode",
              os.stat(data).st_mode & 0o777 == 0o644,
              f"mode changed to {oct(os.stat(data).st_mode & 0o777)}")


# -------------------------------------------------------- stderr truncation

def test_compose_progress_is_stripped_so_the_error_survives():
    """The 200-character HEAD of compose's stderr was all progress chatter; the
    only line that mattered was last. This is why three diagnoses of the ELK
    failure were wrong before anyone read the raw log."""
    stderr = "\n".join(
        [f" Container intact_elk_{n}  {v}"
         for n in ("setup", "kibana", "logstash") for v in ("Creating", "Created", "Starting")]
        + [' Container intact_elk_setup  service "setup" didn\'t complete '
           'successfully: exit 126'])
    out = ca.strip_compose_progress(stderr)
    check("the real error survives", "exit 126" in out, out)
    check("progress chatter is dropped", "Creating" not in out, out)
    check("the old head-truncation would have lost it",
          "exit 126" not in stderr[:200], "premise no longer holds")


def test_all_progress_falls_back_to_the_tail():
    """If compose said nothing but progress, showing the head is still worse
    than showing the end."""
    stderr = "\n".join(f" Container c{i}  Started" for i in range(40))
    out = ca.strip_compose_progress(stderr)
    check("all-progress falls back to the tail", "c39" in out, out)


def test_it_does_not_eat_a_line_merely_containing_a_verb():
    """'Error response from daemon: ... Created' must not look like progress."""
    out = ca.strip_compose_progress(
        "Error response from daemon: conflict: image is being used by Created")
    check("a real error containing a verb survives", "daemon" in out, out)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)
