"""The release dropdown: cache bypass, the (latest) badge, and prereleases.

Three real problems this pins, all of which shipped:

  * A release published BEFORE its CI package finished uploading was filtered
    out (correctly -- no package, not installable) and that answer was cached
    for 30 minutes. The refresh button read the same cache, so it could not
    break out of it; the only recovery was restarting the backend. Forced
    fetches now skip the cache read.

  * The (latest) badge was assigned by LIST POSITION -- first non-draft in
    GitHub's newest-first ordering. GitHub honours the maintainer's "Set as
    the latest release" choice, so a release cut for testing and deliberately
    not promoted is newer yet not latest. The badge advertised exactly such a
    release to every operator as the one to upgrade to. It now comes from
    GitHub's own /releases/latest.

  * Prereleases were hidden entirely, leaving no way to publish a test release
    that is installable on purpose without also advertising it as current.
    They now show, labelled, and can never carry (latest).

Run: docker exec intact_backend python /app/workdir/tests/test_upgrade_refs_listing.py
"""

import sys

if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.upgrade import resolver as R  # noqa: E402


def _asset(tag, size=10 * 1024 * 1024):
    return {"name": f"intact-upgrade-{tag}.tar.gz", "size": size}


def _rel(tag, draft=False, prerelease=False, with_pkg=True):
    return {"tag_name": tag, "draft": draft, "prerelease": prerelease,
            "assets": [_asset(tag)] if with_pkg else []}


class _Resp:
    def __init__(self, payload, status=200):
        self._p, self.status_code = payload, status

    def json(self):
        return self._p


class _FakeGH:
    """Serves /releases and /releases/latest, counting calls."""

    def __init__(self, releases, latest_tag, latest_status=200):
        self.releases, self.latest_tag = releases, latest_tag
        self.latest_status = latest_status
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append(url)
        if url.endswith("/releases/latest"):
            if self.latest_status != 200:
                return _Resp({}, self.latest_status)
            return _Resp({"tag_name": self.latest_tag})
        return _Resp(self.releases)


def _run(fake):
    R._cache.clear()
    orig = R.requests.get
    R.requests.get = fake.get
    try:
        return R.list_github_refs(force=True)
    finally:
        R.requests.get = orig


def _labels(refs):
    return {r["name"]: r["label"] for r in refs}


def test_latest_badge_follows_github_not_list_position():
    """The newest release is NOT automatically latest."""
    fake = _FakeGH([_rel("intact-20260728"), _rel("intact-20260726"),
                    _rel("intact-20260615")], latest_tag="intact-20260726")
    labels = _labels(_run(fake))
    assert labels["intact-20260726"].endswith("(latest)"), labels
    assert "(latest)" not in labels["intact-20260728"], (
        "the newest release was badged (latest) by list position — GitHub says "
        "intact-20260726 is latest, and an unpromoted test release must not be "
        "advertised as the one to upgrade to")


def test_prereleases_are_shown_but_never_latest():
    fake = _FakeGH([_rel("intact-20260801", prerelease=True),
                    _rel("intact-20260726")], latest_tag="intact-20260726")
    refs = _run(fake)
    labels = _labels(refs)
    assert "intact-20260801" in labels, "prerelease vanished from the dropdown"
    assert "(pre-release)" in labels["intact-20260801"], labels
    assert "(latest)" not in labels["intact-20260801"]
    assert labels["intact-20260726"].endswith("(latest)")
    pre = [r for r in refs if r["name"] == "intact-20260801"][0]
    assert pre["prerelease"] is True and pre["latest"] is False


def test_drafts_stay_hidden():
    """Nobody can install a draft."""
    fake = _FakeGH([_rel("intact-20260901", draft=True), _rel("intact-20260726")],
                   latest_tag="intact-20260726")
    assert "intact-20260901" not in _labels(_run(fake))


def test_release_without_a_package_is_still_hidden():
    """The original filter must survive: no package, not an upgrade target.
    This is what made a just-published release invisible until CI finished --
    correct behaviour, and the reason the cache bypass matters."""
    fake = _FakeGH([_rel("intact-20260728", with_pkg=False), _rel("intact-20260726")],
                   latest_tag="intact-20260726")
    assert "intact-20260728" not in _labels(_run(fake))


def test_force_bypasses_the_cache_but_plain_calls_still_hit_it():
    fake = _FakeGH([_rel("intact-20260726")], latest_tag="intact-20260726")
    R._cache.clear()
    orig = R.requests.get
    R.requests.get = fake.get
    try:
        R.list_github_refs(force=True)
        n_after_first = len(fake.calls)
        R.list_github_refs()                       # cached — no new calls
        assert len(fake.calls) == n_after_first, (
            "an unforced call re-queried GitHub; the 30-minute cache is gone")
        R.list_github_refs(force=True)             # forced — must re-query
        assert len(fake.calls) > n_after_first, (
            "force=True served the cached list — this is exactly the bug where "
            "the refresh button could not surface a newly-built package")
    finally:
        R.requests.get = orig


def test_a_forced_fetch_refreshes_a_stale_cached_answer():
    """The real scenario: the package finished uploading AFTER the last fetch."""
    building = _FakeGH([_rel("intact-20260728", with_pkg=False), _rel("intact-20260726")],
                       latest_tag="intact-20260726")
    R._cache.clear()
    orig = R.requests.get
    R.requests.get = building.get
    try:
        assert "intact-20260728" not in _labels(R.list_github_refs(force=True))
        # CI finishes; assets appear.
        done = _FakeGH([_rel("intact-20260728"), _rel("intact-20260726")],
                       latest_tag="intact-20260726")
        R.requests.get = done.get
        assert "intact-20260728" not in _labels(R.list_github_refs()), \
            "unforced call should still serve the cached (stale) list"
        assert "intact-20260728" in _labels(R.list_github_refs(force=True)), \
            "a forced fetch did not pick up the now-published package"
    finally:
        R.requests.get = orig


def test_missing_github_latest_degrades_to_no_badge():
    """/releases/latest 404s on a repo with no promoted release. A missing
    badge is cosmetic; it must not empty the dropdown."""
    fake = _FakeGH([_rel("intact-20260726")], latest_tag=None, latest_status=404)
    refs = _run(fake)
    assert len(refs) == 1, "dropdown lost entries when /releases/latest failed"
    assert "(latest)" not in refs[0]["label"]


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
