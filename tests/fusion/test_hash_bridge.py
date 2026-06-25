"""Hash-identity bridge — the same binary keyed by different algos collapses to ONE
cross-host IOC node.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion import correlate, keys  # noqa: E402
from services.fusion.mappers import map_agentic  # noqa: E402

SHA256 = "a" * 64
SHA1 = "b" * 40


def test_amcache_sha1_collapses_into_pslist_sha256():
    # host A: Amcache row (SHA1 only). host B: Pslist unsigned binary carrying SHA256+SHA1.
    cdA = {"DetectRaptor.Windows.Detection.Amcache": [
        {"EntryName": "evil.exe", "SHA1": SHA1, "_client_id": "C.a", "_hostname": "A"}]}
    cdB = {"Windows.System.Pslist": [
        {"Pid": 10, "Ppid": 4, "Name": "evil.exe", "Exe": "C:\\Users\\x\\Temp\\evil.exe",
         "CreateTime": "2026-06-15T08:00:00Z",
         "Hash": {"SHA256": SHA256, "SHA1": SHA1, "MD5": "c" * 32},
         "Authenticode": {"Trusted": "untrusted"}, "_client_id": "C.b", "_hostname": "B"}]}
    cA = map_agentic(cdA, run_id="a", hostnames={"C.a": "A"})
    cB = map_agentic(cdB, run_id="b", hostnames={"C.b": "B"})
    g = correlate.assemble("bridge", [cA, cB], ["a", "b"])

    hashes = [e for e in g.by_type("ioc") if e.attrs.get("ioc_kind") == "hash"]
    assert len(hashes) == 1, f"SHA1 + SHA256 of same binary must be ONE node, got {len(hashes)}"
    node = hashes[0]
    assert node.id == keys.ioc_id("hash", SHA256), "canonical key is the SHA256"
    assert set(node.attrs.get("_assets") or []) >= {keys.asset_id("C.a"), keys.asset_id("C.b")}, \
        "merged node spans both hosts"


def test_bridged_binary_yields_one_cross_host_finding():
    # the merged binary is unsigned (anomaly>=1 from Pslist) on 2 hosts -> exactly ONE
    # 'seen on N hosts' finding (not two).
    cdA = {"DetectRaptor.Windows.Detection.Amcache": [
        {"EntryName": "evil.exe", "SHA1": SHA1, "_client_id": "C.a", "_hostname": "A"}]}
    cdB = {"Windows.System.Pslist": [
        {"Pid": 10, "Ppid": 4, "Name": "evil.exe", "Exe": "C:\\Users\\x\\Temp\\evil.exe",
         "CreateTime": "2026-06-15T08:00:00Z",
         "Hash": {"SHA256": SHA256, "SHA1": SHA1}, "Authenticode": {"Trusted": "untrusted"},
         "_client_id": "C.b", "_hostname": "B"}]}
    g = correlate.assemble("bridge", [map_agentic(cdA, run_id="a", hostnames={"C.a": "A"}),
                                      map_agentic(cdB, run_id="b", hostnames={"C.b": "B"})],
                           ["a", "b"])
    xh = [f for f in g.findings if "seen on" in f.title.lower() and "hosts" in f.title.lower()]
    assert len(xh) == 1, f"one shared-binary finding expected, got {len(xh)}"


def test_no_aliasing_without_a_paired_sha256():
    # a lone SHA1 node (no sha256 twin anywhere) stays as itself — no false merge.
    cd = {"DetectRaptor.Windows.Detection.Amcache": [
        {"EntryName": "x.exe", "SHA1": SHA1, "_client_id": "C.a", "_hostname": "A"}]}
    g = correlate.assemble("x", [map_agentic(cd, run_id="a", hostnames={"C.a": "A"})], ["a"])
    hashes = [e for e in g.by_type("ioc") if e.attrs.get("ioc_kind") == "hash"]
    assert len(hashes) == 1 and hashes[0].id == keys.ioc_id("hash", SHA1)


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
