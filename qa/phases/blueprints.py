"""Blueprints — what every collection in the product is defined by, CRUD-untested.

WHY THIS MATTERS. A blueprint is the unit of work: `pipelines`, `hunt_linux`,
`scheduler` and the memory module all take a blueprint id and run what it says.
The suite listed them and picked one; nothing ever created, edited or deleted
one. Three of the four families (timesketch, memory, and the per-id routes of
all of them) had no caller at all.

TWO PROPERTIES ARE ON TEST, and they pull in opposite directions:

  * an operator's OWN blueprint must round-trip -- created, fetched by id,
    edited, and deleted again. A tool whose customisation does not persist is a
    tool everyone re-customises on every engagement.
  * a SHIPPED blueprint must be undeletable. Defaults re-seed from YAML on
    boot, so a deleted one appears to come back and the operator's edit is
    silently discarded; worse, anything referencing it -- a saved schedule, a
    saved case config -- points at nothing until the next restart. The product
    refuses with 400 "Cannot delete default blueprints", and that refusal is
    load-bearing.

The three families are driven from one table because they share an
implementation (agentic POST/PUT/DELETE literally call the velociraptor ones),
so a divergence between them is itself worth catching.

Shapes verified against a live backend: create answers 201 with the record
nested under `blueprint`, and defaults carry is_default: true.
"""

# family -> the extra field its create needs beyond name/description.
_FAMILIES = (
    ("velociraptor", {"artifacts": ["Generic.Client.Info"]}),
    ("timesketch",   {"parsers": ["winevtx"]}),
    ("memory",       {"plugins": ["windows.pslist"]}),
)


def _list(c, fam):
    body = c.get(f"/api/blueprints/{fam}")
    if isinstance(body, list):
        return body
    return (body or {}).get("blueprints") or []


def register(runner, cfg):

    @runner.phase("blueprints",
                  "Round-trip a custom blueprint and prove the defaults are protected",
                  needs=("features",))
    def blueprints(ctx):
        c = ctx.get("client")
        detail = {}

        for fam, extra in _FAMILIES:
            seeded = _list(c, fam)
            detail[f"{fam}_count"] = len(seeded)
            ctx.check(f"{fam} blueprints are seeded", len(seeded) > 0,
                      expected=">0", actual=len(seeded),
                      note="defaults re-seed from YAML on boot; an empty family "
                           "means the seeding did not run and nothing in that "
                           "module can be dispatched")
            if not seeded:
                continue

            # --- the operator's own blueprint round-trips -----------------
            made = c.post(f"/api/blueprints/{fam}",
                          {"name": f"QA CI {fam} blueprint",
                           "description": "created by the e2e suite", **extra},
                          expect=(200, 201))
            rec = (made or {}).get("blueprint") or made or {}
            bid = rec.get("id")
            detail[f"{fam}_created"] = bid
            ctx.check(f"a custom {fam} blueprint is created", bool(bid),
                      actual=made)
            if not bid:
                continue

            try:
                got = c.get(f"/api/blueprints/{fam}/{bid}", expect=(200, 404))
                ctx.check(f"the new {fam} blueprint is fetchable by id",
                          isinstance(got, dict) and got.get("id") == bid,
                          expected=bid, actual=(got or {}).get("id"))
                ctx.check(f"a created {fam} blueprint is not marked default",
                          not (got or {}).get("is_default"),
                          actual=(got or {}).get("is_default"),
                          note="a custom blueprint that inherits the default "
                               "flag becomes undeletable, and the operator "
                               "cannot clean up their own mistake")

                c.request("PUT", f"/api/blueprints/{fam}/{bid}",
                          json={"name": "QA CI renamed"}, expect=(200, 201))
                after = c.get(f"/api/blueprints/{fam}/{bid}", expect=(200, 404))
                ctx.check(f"editing a {fam} blueprint persists",
                          (after or {}).get("name") == "QA CI renamed",
                          expected="QA CI renamed", actual=(after or {}).get("name"))
            finally:
                c.delete(f"/api/blueprints/{fam}/{bid}",
                         expect=(200, 202, 204, 404))

            gone = c.status_of(f"/api/blueprints/{fam}/{bid}")
            ctx.check(f"a deleted {fam} blueprint is gone", gone == 404,
                      expected=404, actual=gone)

            # --- the shipped ones must NOT be removable -------------------
            default = next((b for b in seeded if b.get("is_default")), None)
            if not default:
                ctx.check(f"{fam} ships a default blueprint to protect", False,
                          actual=[b.get("id") for b in seeded][:4],
                          note="none is flagged is_default, so the protection "
                               "below cannot be exercised -- and nothing stops "
                               "an operator deleting a shipped blueprint")
                continue

            did = default.get("id")
            code = c.status_of(f"/api/blueprints/{fam}/{did}")
            refused = c.request("DELETE", f"/api/blueprints/{fam}/{did}",
                                expect=(400, 403, 409))
            detail[f"{fam}_default"] = did
            ctx.check(f"a default {fam} blueprint cannot be deleted", True,
                      actual=str(refused)[:90],
                      note="the DELETE is expected to be REFUSED; `expect` here "
                           "would have raised on a 200, so reaching this line "
                           "is the assertion")
            still = c.status_of(f"/api/blueprints/{fam}/{did}")
            ctx.check(f"the default {fam} blueprint survived the attempt",
                      still == 200 and code == 200,
                      expected="200 before and after", actual=f"{code} -> {still}",
                      note="a refusal that still deletes is worse than no "
                           "refusal, because the UI reports it as prevented")
        return detail
