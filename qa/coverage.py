"""What a run must actually EXERCISE before it may call itself green.

THE BUG THIS EXISTS FOR. Every scenario in run 34018978136 reported success
while skipping seven phases, and the skips were invisible because they were
constant: `kape`, `kape_gate`, `hunt`, `timesketch`, `volweb` and `fusion` all
cascaded from "activity did not run", and `refuse-and-repeat` additionally
skipped the downgrade half it exists to prove because its tag resolved empty.
A board of twelve green scenarios was covering less than it looked, and nothing
said so -- the workflow header still claims every scenario "runs the
Velociraptor / Timesketch / fusion pipelines".

Two mechanisms, because they fail differently:

  REQUIRED   phases that must genuinely run. A skip here fails the run, so a
             regression that quietly disables a pipeline cannot hide behind a
             pass. This is the coverage FLOOR.

  KNOWN_GAPS phases that legitimately do not run in this profile, each with the
             reason. Listing them is the point: an expected skip is documented
             coverage we do not have, and an UNEXPECTED skip -- one in neither
             set -- fails, because that is what a regression looks like.

WHAT IS ACTUALLY COVERED, since the phase names mislead. `pipelines` is the
workhorse: it plants Linux evidence, collects it through Velociraptor, uploads
the windows job's real .evtx through the product's own tus endpoint and asserts
plaso ingested it, and fuses a case. So Velociraptor, Timesketch and fusion all
have real coverage. The Windows-endpoint chain below is a SECOND path to the
same modules, not the only one -- except memory/VolWeb, which has none.
"""

# Runs on every scenario, on the Linux profile CI actually uses.
REQUIRED_ALWAYS = (
    "install",          # the box came up
    "auth",             # the dashboard is reachable and a session works
    "enrol_linux",      # a real client checked in
    "features",         # the API sweep
    "pipelines",        # plants Linux evidence, collects it, and FUSES it
    "hunt_linux",       # a fleet hunt, not just a per-client collection
    "memory_plumbing",  # the memory module's only coverage
    "case_read",        # the Case Analysis surface an analyst opens
    "case_report",      # the DETERMINISTIC report assembles
    "case_pdf",         # the branded deliverable renders
    "case_mutations",   # triage actually persists
    "purge_scan",       # a section cannot honestly scan zero on a filled box
    "purge_run",        # the bytes actually go
    "collect",
    "report",
)

# route -> the phases that route must run. A scenario claiming to test an
# upgrade path has not tested it if these skipped.
REQUIRED_BY_ROUTE = {
    "bootstrap": ("upgrade", "verify_upgrade"),
    "cli":       ("upgrade", "verify_upgrade"),
    "ui_online": ("upgrade", "verify_upgrade"),
    "ui_import": ("upgrade", "verify_upgrade"),
}

# Phases that do not run on the Linux profile, and why. NOT a licence to ignore
# them -- this is the list of things a green board does not prove, and it should
# get shorter, not longer.
KNOWN_GAPS = {
    "enrol":      "no Windows endpoint is enrolled on the Linux profile",
    "activity":   "needs the Windows endpoint (enrol)",
    "export":     "needs the Windows endpoint (enrol)",
    "kape":       "KAPE collection is Windows-only; needs activity",
    "kape_gate":  "gates on the KAPE collection above",
    "hunt":       "dispatched against the Windows collection",
    "timesketch": "this phase ingests the VELOCIRAPTOR-COLLECTED KAPE output. "
                  "The Timesketch pipeline itself IS exercised: the windows job "
                  "harvests real .evtx, and `pipelines` uploads it through the "
                  "product's own tus endpoint and asserts plaso extracted events "
                  "in proportion to it. What is missing is the collection half.",
    "volweb":     "the windows runner cannot load a memory-acquisition driver, "
                  "so no image is produced and the memory pipeline reports "
                  "SKIPPED. This is the one pipeline with NO coverage at all.",
    "fusion":     "the WINDOWS three-source fusion; the Linux `pipelines` phase "
                  "fuses a case of its own, so fusion itself is still covered",
    "wipe":       "a fresh runner has nothing to tear down",
}


def required_for(route):
    """Every phase this run must actually have executed."""
    return tuple(REQUIRED_ALWAYS) + tuple(REQUIRED_BY_ROUTE.get(route or "", ()))


def audit(results, route):
    """(missing, unexpected) — what a green run failed to prove.

    `results` maps phase name -> an object with .status. A phase absent from
    `results` was never registered, which for a REQUIRED phase is the same
    failure as skipping it and must not read as a pass.
    """
    missing, unexpected = [], []
    for name in required_for(route):
        res = results.get(name)
        status = getattr(res, "status", None) if res is not None else None
        if status != "pass":
            missing.append((name, status or "never registered"))
    for name, res in sorted(results.items()):
        if getattr(res, "status", None) != "skip":
            continue
        if name in KNOWN_GAPS or name in required_for(route):
            continue        # documented, or already reported as missing above
        unexpected.append((name, getattr(res, "skipped_because", None) or "?"))
    return missing, unexpected
