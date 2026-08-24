"""The scenario catalogue — one source of truth for the workflow AND the harness.

Both used to carry their own copy: a list inside .github/workflows/e2e.yml
deciding which jobs run, and a route map in qa/phases/upgrade.py deciding which
phases each one registers. Nothing at runtime checked they agreed, and when the
fusion allowlist and the Linux blueprint drifted exactly that way, nine
artefacts were collected and silently discarded for weeks. A guard test can
catch drift; one list cannot drift at all.

VERSIONS ARE NAMED BY ROLE, NOT BY TAG. A scenario says it starts from the
OLDEST supported box or the PREVIOUS release; the concrete tag is resolved when
the workflow runs. That is what stops this file needing an edit every release —
and it is also more honest, because "the release before this one" is the thing
the test actually means.

Only one role is pinned, and deliberately: OLDEST is a property of code history
rather than of dates. Installability changed at a specific commit (the release
package became the only source of images), so the oldest installable box is a
fact about that boundary, not something to compute from a release list.
"""

# The oldest release that can still be installed from scratch.
#
# Pinned because it is a statement about history: releases from this era pull
# their images from registries, which is why they need no assets. Everything
# after the cutover takes images only from a published release package, and
# intact-20260811 in particular cannot be installed at all — its VERSION names
# a release that was never published and its only asset is intact-only.
OLDEST_INSTALLABLE = "intact-20260615"

# The oldest box that is still in the field and cannot upgrade itself: it ships
# no scripts/upgrade.sh and no bootstrap at all, so the target release's code
# has to drive. Verified against the tag.
OLDEST_WITHOUT_ENGINE = "intact-20260726"

# The first release that carries an on-disk engine. A dashboard upgrade runs ON
# the box, so reaching it is what lets the UI routes be tested from a version
# that has one.
FIRST_WITH_ENGINE = "intact-20260811"

# Roles a scenario may name instead of a tag. The workflow resolves these at
# dispatch time; PREVIOUS comes from the release list, the rest are the pins
# above.
ROLES = {
    "OLDEST": OLDEST_INSTALLABLE,
    "OLDEST_NO_ENGINE": OLDEST_WITHOUT_ENGINE,
    "FIRST_ENGINE": FIRST_WITH_ENGINE,
    "PREVIOUS": None,          # resolved from the releases list at run time
}

# route -> what it exercises. A scenario with no route is install-only.
ROUTES = {
    "bootstrap": "the frozen doorman fetches the target engine",
    "cli":       "scripts/upgrade.sh, the documented operator path",
    "ui_online": "POST /api/upgrade/online",
    "ui_import": "prepare a package, then apply it",
}

# modules: what the box should have when it is installed.
#   all           every module, including the one disabled by default
#   shipped       exactly what that release ships — a faithful old box
#   backend-only  every module explicitly off; backend and nginx are unconditional
MODULE_SETS = ("all", "shipped", "backend-only")

SCENARIOS = [
    {"name": "install-online", "install_from": None, "install_mode": "online",
     "modules": "all", "route": None,
     "proves": "the ordinary install"},

    {"name": "install-package", "install_from": None, "install_mode": "package",
     "modules": "all", "route": None,
     "proves": "the air-gap install; --package diverges from online in ~15 places"},

    {"name": "cli-upgrade", "install_from": "OLDEST", "install_mode": "online",
     "modules": "all", "route": "cli",
     "proves": "the upgrade path the README documents to operators, run from "
               "the oldest installable box — safe to test from here because "
               "the box's own engine is never invoked (see _shell_route's "
               "'cli' branch): the operator downloads the TARGET release's "
               "own tree and runs that, so an old or broken local engine "
               "plays no part"},

    {"name": "bootstrap", "install_from": "OLDEST", "install_mode": "online",
     "modules": "all", "route": "bootstrap",
     "proves": "a box too old to have an engine can still be moved"},

    # KNOWN RED, and deliberately not worked around.
    #
    # intact-20260811 has no partial-fetch branch in lib/upgrade/package.sh:
    # `INTACT_RELEASE_ONLY_MODULES` appears there zero times. The dashboard
    # route downloads only the modules the plan names, then 0811 verifies the
    # merged manifest for ALL of them, finds the ones it never fetched missing,
    # and refuses its own package. The box runs 0811's upkg_acquire before it
    # can hand over to the target's code, so nothing in this tree can reach it.
    #
    # It is already fixed here — that branch exists in the current engine — so
    # this scenario turns green on its own the day the matrix hops through a
    # release that carries the fix. Nobody should spend an afternoon
    # rediagnosing it before then, and nothing should be special-cased to make
    # a dead release pass.
    {"name": "ui-online-full", "install_from": "OLDEST_NO_ENGINE",
     "install_mode": "online", "modules": "shipped", "route": "ui_online",
     "hop_via": "FIRST_ENGINE",
     "proves": "the dashboard upgrade, from a box that genuinely has an engine"},

    {"name": "ui-import-full", "install_from": "OLDEST_NO_ENGINE",
     "install_mode": "online", "modules": "shipped", "route": "ui_import",
     "hop_via": "FIRST_ENGINE",
     "proves": "the air-gap dashboard upgrade"},

    # install_mode is `package` for both, and that is load-bearing rather than
    # incidental. A backend-only box disables timesketch, and timesketch ships
    # its own nginx -- so app.py's disabled-module prune reclaims the bare
    # `nginx` repo, which is where the PLATFORM's reverse proxy also lives, and
    # deletes it between the backend starting (step 7 of 8) and nginx being
    # deployed (step 8). The install then dies on "No such image".
    #
    # The fix lives in this tree, but the prune runs INSIDE the backend
    # container, and on an online install that container is the release's
    # image -- which does not carry the fix and will not until a release ships
    # it. Package mode is what lets the harness put this ref's backend on the
    # box before the install needs it.
    #
    # What is given up is small: the adopt pair exists to test adoption via
    # UPGRADE, not the install route, and install-online already covers an
    # online install.
    {"name": "ui-online-adopt", "install_from": None, "install_mode": "package",
     "modules": "backend-only", "route": "ui_online",
     "proves": "a customer adopts a feature they never had"},

    {"name": "ui-import-adopt", "install_from": None, "install_mode": "package",
     "modules": "backend-only", "route": "ui_import",
     "proves": "the same adoption, air-gapped end to end"},

    {"name": "rollback", "install_from": None, "install_mode": "online",
     "modules": "all", "route": "cli",
     "extra": "--only portainer --reinstall portainer",
     "proves": "a failed module unwinds instead of stranding the box"},

    {"name": "data-preservation", "install_from": None, "install_mode": "online",
     "modules": "all", "route": "cli", "extra": "--reinstall iris",
     "proves": "an upgrade does not lose what the box was holding"},

    {"name": "refuse-and-repeat", "install_from": None, "install_mode": "online",
     "modules": "all", "route": "cli",
     "extra": "--only portainer --reinstall portainer",
     "downgrade_from": "PREVIOUS",
     "proves": "a refusal touches nothing, and a re-run is a no-op"},
]

BY_NAME = {s["name"]: s for s in SCENARIOS}


def route_for(name):
    """The upgrade route a scenario uses, or None if it only installs."""
    return (BY_NAME.get(name) or {}).get("route")


def resolve(names, previous_tag=None):
    """Turn scenario names into rows with concrete tags.

    `previous_tag` supplies the PREVIOUS role. Left unresolved, a scenario that
    needs it simply carries an empty value and the check that uses it says so —
    better than inventing a tag that would be refused for the wrong reason.
    """
    def tag(role):
        if role is None:
            return ""
        if role == "PREVIOUS":
            return previous_tag or ""
        return ROLES.get(role, role)          # unknown role: assume a literal tag

    rows = []
    for name in names:
        spec = BY_NAME[name]
        rows.append({
            "scenario": name,
            "install_from": tag(spec.get("install_from")),
            "install_mode": spec["install_mode"],
            "modules": spec["modules"],
            "upgrade_route": spec.get("route") or "",
            "upgrade_extra": spec.get("extra", ""),
            "hop_via": tag(spec.get("hop_via")),
            "downgrade_tag": tag(spec.get("downgrade_from")),
        })
    return rows
