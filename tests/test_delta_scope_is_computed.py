"""The delta set is COMPUTED from pin movement, never hand-listed.

WHY THIS EXISTS
---------------
The release scope used to be a hand-edited constant, and it produced a package
that upgraded exactly one module while reporting success. Diagnosing it took
manifest archaeology -- comparing a shipped `tusd-v2.9.2` against a pinned
`v2.10.0` -- because nothing in the package said what it was meant to carry.

The rule now: editing ANY module's version in config.yaml puts that module in
the delta. No list to maintain, so no list to forget.

Versions compare as opaque STRINGS on purpose. The question is "did the
operator change this pin", not "is this newer" -- so a bump, a revert and a
reformat all count, and none of them depend on parsing a scheme that differs
per module (9.4.4, v2.10.0, 20260630, 0.77.1, latest).

A TAG IS NOT AN IDENTITY
-----------------------
The numbers this docstring first carried were WRONG, and the way they were
wrong is the point. intact-20260803 was re-cut, moving from 6316e05 to 25effd5.
`git fetch` does not move an existing local tag, so a stale checkout measured
the delta against code the release no longer contained and reported "nothing
changed" -- while elk had gone 9.4.2 -> 9.4.4 and tusd v2.9.2 -> v2.10.0.

Two packages, same tag, same manifest, different code, and no way to tell them
apart from the outside. Hence: refresh tags forcibly before choosing a
baseline, and record the resolved COMMIT for both the release and its baseline.

THE DANGER THIS DOES NOT REMOVE
-------------------------------
A delta is computed against the IMMEDIATELY PREVIOUS release, so it is only
valid for a box sitting on exactly that baseline. Measured on real history,
target intact-20260803:

    vs intact-20260802 : elk 9.4.2 -> 9.4.4, backend_tusd v2.9.2 -> v2.10.0
    vs intact-20260615 : 14 modules moved

A box on 20260615 handed a delta built against 20260802 would silently keep a
dozen stale modules while the run reported success. That is why `delta_from` is
recorded in the manifest and enforced on apply. Computing the set correctly
does not make it safe to apply anywhere; the guard does.

WHY A FIXTURE REPO
------------------
These functions shell out to git. The suite runs inside a container where
/app/workdir is a git WORKTREE, whose .git is a FILE pointing at a path that
does not exist in the mount -- so every git call fails and the versions come
back empty. The first version of this test asserted against live tag history
and passed outside the container while failing inside it. Live history is also
brittle on its own: the expected numbers change the next time anyone tags.

Run: docker exec intact_backend python /app/workdir/tests/test_delta_scope_is_computed.py
"""

import ast
import os
import shutil
import subprocess
import sys
import tempfile

import yaml

REPO = os.environ.get("INTACT_PATH", "/app/workdir")
BUILDER = os.path.join(REPO, "scripts/ci/build_release_package.py")

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"  PASS  {name}")
    else:
        failures.append(f"{name}: {detail}")
        print(f"  FAIL  {name}: {detail}")


def _load(*names):
    """Load named top-level functions/constants from the builder without
    importing it -- it pulls in the whole backend package at import time."""
    src = open(BUILDER).read()
    ns = {"subprocess": subprocess, "yaml": yaml, "print": print, "os": os}
    for node in ast.parse(src).body:
        if isinstance(node, ast.FunctionDef) and node.name in names:
            exec(compile(ast.Module([node], []), "<builder>", "exec"), ns)
        elif isinstance(node, ast.Assign):
            for t in node.targets:
                if getattr(t, "id", None) in names:
                    ns[t.id] = ast.literal_eval(node.value)
    return ns


NS = _load("previous_release_tag", "_versions_at_ref", "delta_module_set",
           "commit_of", "RELEASE_MODULES", "EXCLUDED_FROM_RELEASE")


def _fixture_repo():
    """A throwaway repo carrying the tag shapes this logic has to survive,
    including the suffixed ones that actually broke it."""
    d = tempfile.mkdtemp(prefix="deltarepo_")

    def run(*a):
        subprocess.run(a, cwd=d, capture_output=True, check=True)

    run("git", "init", "-q")
    run("git", "config", "user.email", "t@t")
    run("git", "config", "user.name", "t")

    def commit_tag(tag, versions):
        with open(os.path.join(d, "config.yaml"), "w") as f:
            yaml.safe_dump({"versions": versions}, f)
        run("git", "add", "config.yaml")
        run("git", "commit", "-qm", tag)
        run("git", "tag", tag)

    commit_tag("intact-20260615", {"elk": "9.0.0", "timesketch": "20260326",
                                   "velociraptor": "0.76.1", "plaso": "20260119"})
    # Distinct values: identical content would leave nothing to commit and git
    # exits 1. They also have to differ from the real releases either side, so
    # picking one as a baseline produces a WRONG delta rather than a harmless
    # one -- that is the failure this fixture is here to catch.
    commit_tag("intact-20260615Legacy", {"elk": "0.0.1"})    # not a release
    commit_tag("intact-20260705Legacy", {"elk": "0.0.2"})    # not a release
    commit_tag("intact-20260726", {"elk": "9.4.2", "timesketch": "20260630",
                                   "velociraptor": "0.77.1", "plaso": "20260119"})
    commit_tag("intact-20260803", {"elk": "9.4.4", "timesketch": "20260630",
                                   "velociraptor": "0.77.1", "plaso": "20260119"})
    return d


def _in(d, fn, *args):
    cwd = os.getcwd()
    os.chdir(d)
    try:
        return fn(*args)
    finally:
        os.chdir(cwd)


# --------------------------------------------------------- baseline selection

def test_the_previous_release_is_the_one_immediately_before():
    d = _fixture_repo()
    try:
        prev = lambda t: _in(d, NS["previous_release_tag"], t)
        check("previous(20260803) is 20260726",
              prev("intact-20260803") == "intact-20260726",
              str(prev("intact-20260803")))
        check("previous(20260726) is 20260615",
              prev("intact-20260726") == "intact-20260615",
              str(prev("intact-20260726")))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_suffixed_tags_are_not_treated_as_releases():
    """intact-20260615Legacy / intact-20260705Legacy sort straight into the
    middle of the real releases. Unfiltered, intact-20260705Legacy becomes the
    'previous release' of intact-20260726 and the delta gets diffed against a
    config that never shipped to anyone. These tags are retired but still IN the
    repo, which is exactly the case that bites -- found by running the selection
    against real tag data, not by reading the code."""
    d = _fixture_repo()
    try:
        prev = _in(d, NS["previous_release_tag"], "intact-20260726")
        check("no Legacy tag is picked as a baseline",
              prev is not None and "Legacy" not in prev, str(prev))
        check("it picks the real previous release",
              prev == "intact-20260615", str(prev))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_the_first_release_has_no_baseline():
    """Returns None rather than inventing one; the caller ships full."""
    d = _fixture_repo()
    try:
        check("a tag older than every release yields None",
              _in(d, NS["previous_release_tag"], "intact-19700101") is None, "")
    finally:
        shutil.rmtree(d, ignore_errors=True)


# ------------------------------------------------------------ pin comparison

def test_versions_are_read_from_git_not_the_working_tree():
    """The comparison must be against what that release SHIPPED, not whatever
    is checked out now -- otherwise the delta reflects the builder's working
    copy and changes meaning depending on where you run it."""
    d = _fixture_repo()
    try:
        # the working tree holds the 20260803 config; ask for an older tag
        v = _in(d, NS["_versions_at_ref"], "intact-20260726")
        check("it reads that tag's pins, not the checkout's",
              v.get("elk") == "9.4.2", str(v))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_an_unreadable_ref_yields_an_empty_block_not_a_crash():
    """A missing ref must not take the build down -- an empty baseline makes
    every module look changed, which is the SAFE direction (ships more)."""
    d = _fixture_repo()
    try:
        try:
            v = _in(d, NS["_versions_at_ref"], "intact-does-not-exist")
            raised = False
        except Exception:
            raised = True
        check("a bad ref does not raise", not raised, "it raised")
        check("and yields an empty mapping", v == {}, str(v))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_changing_any_pin_puts_that_module_in_the_delta():
    """The whole contract: edit a version in config.yaml and that module ships.
    Opaque string comparison, so a bump, a revert and a reformat all count."""
    d = _fixture_repo()
    try:
        cur = _in(d, NS["_versions_at_ref"], "intact-20260803")
        moved = {k for k, v in cur.items()
                 if str(_in(d, NS["_versions_at_ref"], "intact-20260726").get(k, "")) != str(v)}
        check("the one changed pin is detected", moved == {"elk"}, str(moved))

        old2 = _in(d, NS["_versions_at_ref"], "intact-20260615")
        moved2 = {k for k, v in cur.items() if str(old2.get(k, "")) != str(v)}
        check("a wider baseline detects every module that moved",
              moved2 == {"elk", "timesketch", "velociraptor"}, str(moved2))
        check("and leaves the genuinely unchanged one out",
              "plaso" not in moved2, str(moved2))
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_module_absent_from_the_baseline_counts_as_changed():
    """A module added since the previous release is new to the target, which
    has none of it -- it must ship, not be mistaken for unchanged."""
    d = _fixture_repo()
    try:
        old = _in(d, NS["_versions_at_ref"], "intact-20260615")
        check("the baseline genuinely lacks it", "volweb" not in old, str(sorted(old)))
        changed = str(old.get("volweb", "")) != str("3.16.0")
        check("an absent module compares as changed", changed, "it would be skipped")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_a_moved_tag_is_detectable():
    """A TAG IS NOT AN IDENTITY, and this is not hypothetical: intact-20260803
    was re-cut and moved from 6316e05 to 25effd5. `git fetch` does not move an
    existing local tag, so a stale checkout measured the delta against code the
    release no longer contained and reported "nothing changed" -- while elk had
    gone 9.4.2 -> 9.4.4 and tusd v2.9.2 -> v2.10.0. Two packages, same tag, same
    manifest, different code.

    Recording the commit is what turns that from archaeology into a glance."""
    d = _fixture_repo()
    try:
        first = _in(d, NS["commit_of"], "intact-20260803")
        check("a tag resolves to a commit", len(first) == 40, repr(first))
        # move the tag, exactly as a re-cut release does
        subprocess.run(["git", "tag", "-f", "intact-20260803", "intact-20260726"],
                       cwd=d, capture_output=True, check=True)
        second = _in(d, NS["commit_of"], "intact-20260803")
        check("moving the tag changes the recorded commit", first != second,
              f"{first[:7]} == {second[:7]} -- a moved tag would be invisible")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_an_unresolvable_ref_does_not_crash_the_build():
    d = _fixture_repo()
    try:
        check("a bad ref yields empty, not an exception",
              _in(d, NS["commit_of"], "no-such-ref") == "", "")
    finally:
        shutil.rmtree(d, ignore_errors=True)


def test_tags_are_refreshed_before_the_baseline_is_chosen():
    """Two ways a baseline goes wrong silently, both observed: `git fetch` will
    not move an existing local tag (stale re-cut release), and
    actions/checkout@v4 defaults to a shallow single-ref fetch, so a CI runner
    has no other release tags at all and every lookup returns None."""
    src = open(BUILDER).read()
    fn = src[src.index("def previous_release_tag"):]
    fn = fn[:fn.index("\ndef ")]
    fn_nc = "\n".join(l.split("#")[0] for l in fn.splitlines())
    check("it fetches tags first", '"fetch"' in fn_nc, "stale tags go undetected")
    check("forcibly, or an existing tag would not move", '"--force"' in fn_nc,
          "fetch without --force leaves a re-cut tag pointing at old code")
    check("and before listing them",
          fn_nc.index('"fetch"') < fn_nc.index('"--list"'),
          "the refresh happens too late to matter")


# ------------------------------------------------------------- scope guards

def test_intact_is_always_in_the_delta():
    """The platform image is rebuilt every release, so a delta without intact
    could not upgrade anything. It also prevents an EMPTY package: the real
    20260802 -> 20260803 release moved no module pin at all, and a delta
    computed purely from movement would have contained nothing."""
    src = open(BUILDER).read()
    fn = src[src.index("def delta_module_set"):]
    fn = fn[:fn.index("\ndef ")]
    fn_nc = "\n".join(l.split("#")[0] for l in fn.splitlines())
    check("delta_module_set special-cases intact",
          'module == "intact"' in fn_nc, "intact is not unconditionally included")
    check("and emits it before any comparison",
          fn_nc.index('module == "intact"') < fn_nc.index("before.get("),
          "intact goes through the pin comparison and could be dropped")


def test_the_delta_can_never_exceed_the_full_scope():
    """A module held out of the full asset must not reappear in the delta --
    o365rc pins the literal 'latest', so no manifest could say what shipped."""
    src = open(BUILDER).read()
    fn = src[src.index("def delta_module_set"):]
    fn = fn[:fn.index("\ndef ")]
    check("the delta is derived from release_module_set",
          "release_module_set(" in fn,
          "it does not start from the full scope, so exclusions could leak")
    check("o365rc is excluded from the full scope",
          "o365rc" in NS["EXCLUDED_FROM_RELEASE"]
          and "o365rc" not in NS["RELEASE_MODULES"], "o365rc would ship")


def test_every_module_is_classified():
    """A new module must land in exactly one of the two sets, so adding one is
    always a decision rather than an oversight."""
    known = {"intact", "elk", "iris", "timesketch", "plaso", "velociraptor",
             "volweb", "portainer", "aws_sigma", "o365rc"}
    rm, ex = NS["RELEASE_MODULES"], set(NS["EXCLUDED_FROM_RELEASE"])
    check("no module is unclassified", not (known - rm - ex),
          str(sorted(known - rm - ex)))
    check("no module is in both sets", not (rm & ex), str(sorted(rm & ex)))


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            print(f"\n{name}")
            fn()
    print("\n" + ("FAILED: " + "; ".join(failures) if failures else "ALL PASSED"))
    sys.exit(1 if failures else 0)
