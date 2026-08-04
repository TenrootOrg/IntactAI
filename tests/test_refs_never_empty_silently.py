"""The release picker must not go blank when GitHub has a bad moment.

Reported 2026-08-03: "pick release version is buggy and empty even if I try to
fetch". Every failure path in /api/upgrade/refs returned nothing, so the
operator saw an empty dropdown with no explanation and no way forward.

Four separate causes, all ending in the same blank picker:

  * QUOTA. Two GitHub calls per modal open against an anonymous 60/hr cap. The
    operator's own screenshots showed 46/60 then 30/60 -- opening the dialog a
    dozen times exhausts it, and the quota gate then returned an error before
    even trying.
  * TRANSIENT FAILURES. One dropped connection or a GitHub 5xx emptied the
    list, and the manual retry that followed cost MORE quota than an automatic
    one would have.
  * A CACHED EMPTY. `items` comes back with only the synthetic development
    entry while CI is still attaching package assets, because every release is
    filtered by the `pkg_bytes is None` test. Caching that pinned an empty
    dropdown for the full 30-minute TTL, and the operator's instinct -- open it
    again -- could not clear it.
  * AN UNEXPLAINED EMPTY. "GitHub has no releases" and "GitHub has releases but
    CI has not attached their packages yet" rendered identically, and the second
    is the normal state for the first few minutes after a tag is pushed.

The fix is one idea applied everywhere: a release list from an hour ago is very
nearly as useful as a live one -- releases are cut weekly at most -- and it is
enormously better than none. So every failure serves the last known list,
marked stale with its age, and an empty answer explains which empty it is.

Run: docker exec intact_backend python /app/workdir/tests/test_refs_never_empty_silently.py
"""

import inspect
import sys
import time

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import resolver  # noqa: E402
from routes import upgrade_routes  # noqa: E402

ROUTE = inspect.getsource(upgrade_routes.list_upgrade_refs)
LISTER = inspect.getsource(resolver.list_github_refs)


# ---------------------------------------------------------------------------
# never cache an empty list
# ---------------------------------------------------------------------------

def test_an_empty_release_list_is_not_cached():
    """The one that made it sticky: a 30-minute TTL on 'no releases' meant the
    operator could not clear it by retrying."""
    assert "if any(i.get('kind') == 'tag' for i in items):" in LISTER, (
        "list_github_refs caches unconditionally again — an empty answer will "
        "pin the dropdown blank for the whole TTL")


def test_a_populated_list_is_still_cached():
    """The cache exists to stop page-load chatter burning quota. Disabling it
    entirely would trade one bug for a worse one."""
    assert "_cache_put('refs', items)" in LISTER


# ---------------------------------------------------------------------------
# retry the transient shapes
# ---------------------------------------------------------------------------

def test_transient_failures_are_retried():
    assert "for attempt in range(3):" in LISTER, (
        "a single dropped connection or 5xx empties the dropdown again")
    assert "time.sleep" in LISTER, "retries have no backoff"


def test_rate_limit_and_not_found_are_not_retried():
    """403 and 404 are answers, not accidents. Retrying a rate limit spends
    quota making the rate limit worse."""
    assert "if resp.status_code < 500:" in LISTER, (
        "the retry loop no longer breaks out on a definitive 4xx answer")


# ---------------------------------------------------------------------------
# serve the last known list instead of nothing
# ---------------------------------------------------------------------------

def test_a_stale_read_exists_that_ignores_the_ttl():
    assert hasattr(resolver, "_cache_get_stale"), (
        "no stale reader — the route cannot fall back to the last known list")
    val, age = resolver._cache_get_stale("definitely-not-a-real-key")
    assert val is None and age == 0, (val, age)


def test_the_stale_read_returns_an_expired_entry():
    """Precisely what the normal reader must NOT do, and this one must."""
    resolver._cache_put("t_stale", [{"kind": "tag", "name": "x"}])
    resolver._cache["t_stale"] = (time.time() - (resolver.CACHE_TTL_SECONDS + 60),
                                  [{"kind": "tag", "name": "x"}])
    assert resolver._cache_get("t_stale") is None, "normal read must respect the TTL"
    val, age = resolver._cache_get_stale("t_stale")
    assert val and age > resolver.CACHE_TTL_SECONDS, (val, age)
    resolver._cache.pop("t_stale", None)


def test_every_failure_path_falls_back_to_the_stale_list():
    """Quota, resolver error, unexpected exception, and the empty case."""
    assert ROUTE.count("_stale_or(") >= 4, (
        f"only {ROUTE.count('_stale_or(')} failure paths fall back — one of "
        f"quota / resolver error / empty / unexpected still returns a blank "
        f"dropdown")


def test_the_stale_answer_is_labelled_with_its_age():
    """A stale list presented as current is how an operator misses a release
    that exists. Worse than an empty one, because it looks fine."""
    assert '"stale": True' in ROUTE and '"stale_age_s"' in ROUTE, (
        "the stale fallback does not mark itself, so the UI cannot say where "
        "the list came from")


def test_a_stale_fallback_only_fires_with_real_releases_in_it():
    """Falling back to a cached list that is itself empty achieves nothing and
    hides the error message behind a success response."""
    assert "any(i.get('kind') == 'tag' for i in cached)" in ROUTE, (
        "the route would serve an empty cached list as a successful answer")


# ---------------------------------------------------------------------------
# explain which empty it is
# ---------------------------------------------------------------------------

def test_an_empty_result_explains_itself():
    """'No releases at all' and 'releases exist but CI has not attached their
    packages' look identical in a blank dropdown, and the second is the normal
    state for minutes after a tag is pushed."""
    assert "CI has attached its upgrade package" in ROUTE, (
        "an empty release list no longer explains that CI may still be building")


def test_the_quota_message_says_how_to_raise_the_cap():
    """60/hr anonymous is the root cause of the frequency. The operator can fix
    it permanently, but only if told how."""
    assert "GITHUB_TOKEN" in ROUTE and "5000" in ROUTE, (
        "the quota error does not tell the operator how to raise the cap")


if __name__ == "__main__":
    failures = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
            except Exception as e:      # noqa: BLE001
                failures += 1
                print(f"FAIL {name}: unexpected {type(e).__name__}: {e}")
    print("OK" if not failures else f"{failures} FAILED")
    sys.exit(1 if failures else 0)
