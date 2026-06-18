"""Route-contract tests for the Phase-C case endpoints — shape + 404 over a real fake case,
exercising the HTTP layer (not just the store the routes wrap). Mirrors what the /home/tenroot
QA harness hits over nginx, but in-process so it runs in the gate with no live backend.
"""

import sys
import json
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from flask import Flask  # noqa: E402

from routes.case_routes import case_bp  # noqa: E402
from services.fusion import store, calibrate  # noqa: E402


def _client():
    app = Flask(__name__)
    app.register_blueprint(case_bp)
    return app.test_client()


def _fake_case(c):
    """Create a case + fuse a real attack fixture into it (deterministic, no live infra)."""
    contrib = calibrate._contribution(calibrate.load_fixture("attack2"))
    cid = store.create_case("route-contract-test", min_severity="medium")
    store.fuse_case(cid, contributions_override=[contrib])
    return cid


def _json(resp):
    return json.loads(resp.data)


def test_get_case_exposes_new_keys():
    c = _client()
    cid = _fake_case(c)
    d = _json(c.get(f"/api/cases/{cid}"))
    for k in ("analysis", "dispositions", "token_ab", "llm_enabled", "has_graph"):
        assert k in d, f"GET /<id> missing {k}"
    assert d["has_graph"] is True


def test_new_endpoints_404_on_missing_case():
    c = _client()
    for path, method in [("/api/cases/nope/analysis", "get"),
                         ("/api/cases/nope/dispositions", "get"),
                         ("/api/cases/nope/metrics", "get"),
                         ("/api/cases/nope/baseline", "post")]:
        r = getattr(c, method)(path)
        assert r.status_code == 404, f"{path} should 404, got {r.status_code}"


def test_analysis_endpoint_shape():
    c = _client()
    cid = _fake_case(c)
    d = _json(c.get(f"/api/cases/{cid}/analysis"))
    assert d["case_id"] == cid and "analysis" in d


def test_metrics_endpoint_shape():
    c = _client()
    cid = _fake_case(c)
    d = _json(c.get(f"/api/cases/{cid}/metrics"))
    assert "token_ab" in d and "llm_enabled" in d


def test_disposition_endpoint_requires_target_then_applies():
    c = _client()
    cid = _fake_case(c)
    bad = c.post(f"/api/cases/{cid}/disposition", json={})
    assert bad.status_code == 400, "missing target must 400"
    ok = c.post(f"/api/cases/{cid}/disposition",
                json={"target": "f_anything", "verdict": "benign", "attribution": "it_admin"})
    assert ok.status_code == 200 and "disposition" in _json(ok)
    # the disposition is now persisted + surfaced
    ds = _json(c.get(f"/api/cases/{cid}/dispositions"))["dispositions"]
    assert any(x.get("target") == "f_anything" for x in ds)


def test_baseline_endpoint_returns_fingerprint_summary():
    c = _client()
    cid = _fake_case(c)
    d = _json(c.post(f"/api/cases/{cid}/baseline"))
    assert "baseline" in d and "sigma_titles" in d["baseline"]


def test_runs_picker_contract():
    c = _client()
    d = _json(c.get("/api/cases/runs"))
    assert "runs" in d and isinstance(d["runs"], list)
    for r in d["runs"]:
        assert "run_id" in r and "type" in r


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
        except Exception as e:
            f += 1; print(f"ERR  {fn.__name__}: {type(e).__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
