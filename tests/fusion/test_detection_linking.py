"""Detection-to-entity linking, pinned to the committed real attack fixture.

Proves the keystone: SIGMA detections stop being orphan nodes — they attach to the
process/account/IOC they describe, and short-lived processes Pstree missed are
reconstructed from the detection Details with lineage.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import calibrate, correlate  # noqa: E402


def _attack():
    return calibrate.fuse("attack")


def test_detections_link_to_processes():
    g = _attack()
    ea = [r for r in g.relationships if r.kind == "event_about"]
    assert len(ea) >= 20, "SIGMA detections must attach to processes via event_about"
    # the dst of an event_about must be a sigma event, src a process
    sample = ea[0]
    assert g.entities[sample.dst].type == "event" and "sigma" in g.entities[sample.dst].flags
    assert g.entities[sample.src].type == "process"


def test_short_lived_processes_reconstructed_with_lineage():
    g = _attack()
    fd = [e for e in g.by_type("process") if "from_detection" in e.flags]
    assert fd, "short-lived processes (absent from Pstree) must be created from Details"
    assert all(e.anomaly == 0 for e in fd), "reconstructed processes are anchors, anomaly 0"
    # at least one has a spawned parent edge (ParentPID from Details)
    fd_ids = {e.id for e in fd}
    assert any(r.kind == "spawned" and r.dst in fd_ids for r in g.relationships), \
        "ParentPID from Details should yield a spawned edge"


def test_network_detection_links_process_to_anomaly0_ioc():
    g = _attack()
    conn = [r for r in g.relationships if r.kind == "connected"]
    assert conn, "EID-3 detections must link their process to the target IP"
    # the linked IOCs from Details are anomaly 0 (benign telemetry must not auto-find)
    det_iocs = [e for e in g.by_type("ioc") if e.attrs.get("from_detection")]
    assert det_iocs and all(e.anomaly == 0 for e in det_iocs)


def test_benign_telemetry_ip_on_two_hosts_is_not_cross_host():
    # a from-detection (anomaly 0) IP on 2 hosts must NOT become a 'shared C2' finding,
    # while a real anomaly>=1 IOC on 2 hosts still does.
    from services.fusion.schema import FusionGraph, Entity
    g = FusionGraph(case_id="x")
    benign = Entity(id="ioc:ip:20.42.65.89", type="ioc", label="20.42.65.89", anomaly=0,
                    attrs={"_assets": ["asset:endpoint:C.a", "asset:endpoint:C.b"], "ioc_kind": "ip"})
    real = Entity(id="ioc:ip:5.5.5.5", type="ioc", label="5.5.5.5", anomaly=1,
                  attrs={"_assets": ["asset:endpoint:C.a", "asset:endpoint:C.b"], "ioc_kind": "ip"})
    g.upsert(benign); g.upsert(real)
    correlate._cross_host_findings(g)
    titles = " ".join(f.title for f in g.findings)
    assert "5.5.5.5" in titles and "20.42.65.89" not in titles


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    p = f = 0
    for fn in fns:
        try:
            fn(); p += 1; print(f"PASS {fn.__name__}")
        except AssertionError as e:
            f += 1; print(f"FAIL {fn.__name__}: {e}")
    print(f"{p}/{len(fns)} passed")
    sys.exit(1 if f else 0)
