"""The Velociraptor client list, shared by both enrolment paths.

These four helpers were written for the Windows enrolment and are equally the
right answer for the Linux one. They live here rather than being imported from
qa/phases/endpoint.py because that module now returns early when there is no
Windows target, and because two copies of "which key holds the client list"
would drift — the sort of drift that shows up as an enrolment which silently
looks like it never happened.

Every non-obvious decision below was verified against a live box; the comments
record which, so the next person does not re-learn them from a failing run.
"""


def _clients(c, include_offline=False):
    """The client list, as {client_id: item}.

    The response key is `items`, not `clients` — verified against the live box,
    where the earlier guess would have silently produced an empty set and made
    enrolment look like it never happened.

    `include_offline` matters for teardown: the default is online-only, so a
    client that has merely gone quiet disappears from the list. Verifying that
    an agent was actually REMOVED must ask for offline clients too, or a
    half-finished uninstall reads as a clean one.
    """
    try:
        body = c.get("/api/clients" +
                     ("?include_offline=true" if include_offline else ""))
    except Exception:                                         # noqa: BLE001
        return {}
    items = body.get("items", []) if isinstance(body, dict) else (body or [])
    return {it["client_id"]: it for it in items
            if isinstance(it, dict) and it.get("client_id")}


def _client_ids(c, include_offline=False):
    return set(_clients(c, include_offline))


def _first_new_client(c, before):
    fresh = sorted(_client_ids(c) - before)
    return fresh[0] if fresh else None


def _client_hostname(c, client_id):
    """From the client LIST.

    /api/client/<client_id> exists as a route but returns 501 "Not implemented
    yet" — it is a stub. The list already carries `hostname`, so there is
    nothing to be gained by calling it.
    """
    return (_clients(c, include_offline=True).get(client_id) or {}).get("hostname")
