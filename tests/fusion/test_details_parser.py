"""Pure-function tests for the Hayabusa Details parser — the keystone of Phase 1."""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion.mappers import details as D  # noqa: E402

EID1 = ('Cmdline: "C:\\WINDOWS\\system32\\cmd.exe" /d /c x.cmd ¦ Proc: C:\\Windows\\System32\\cmd.exe'
        ' ¦ User: NT AUTHORITY\\SYSTEM ¦ ParentCmdline: C:\\WINDOWS\\system32\\svchost.exe -k netsvcs'
        ' ¦ PID: 5064 ¦ ParentPID: 1472 ¦ Hashes: MD5=6d109a3a,SHA256=64afc6db,IMPHASH=b0f049c0')
EID3 = ('Initiated: true ¦ Proto: tcp ¦ SrcIP: 192.168.198.150 ¦ TgtIP: 20.42.65.89 ¦ TgtPort: 443'
        ' ¦ User: DESKTOP-566AT85\\vagrant ¦ Proc: C:\\Users\\vagrant\\OneDrive.exe ¦ PID: 4684')
DEFENDER = 'Time: "2026-06-15T08:26:58Z" ¦ User: SYSTEM'


def test_eid1_process_fields():
    d = D.parse_details(EID1)
    assert D.pid(d) == "5064" and D.parentpid(d) == "1472"
    assert D.proc(d) == "C:\\Windows\\System32\\cmd.exe"
    assert D.cmdline(d).startswith('"C:\\WINDOWS\\system32\\cmd.exe"')  # value keeps its colon
    assert D.user(d) == ("NT AUTHORITY", "SYSTEM")
    assert D.hashes(d) == {"md5": "6d109a3a", "sha256": "64afc6db", "imphash": "b0f049c0"}


def test_eid3_network_fields():
    d = D.parse_details(EID3)
    assert D.tgtip(d) == "20.42.65.89" and D.srcip(d) == "192.168.198.150"
    assert D.pid(d) == "4684"
    assert D.user(d) == ("DESKTOP-566AT85", "vagrant")
    assert D.hashes(d) == {}


def test_defender_variant_has_no_process():
    d = D.parse_details(DEFENDER)
    assert D.pid(d) is None and D.proc(d) is None and D.parentpid(d) is None
    assert D.user(d) == (None, "SYSTEM")


def test_malformed_never_raises():
    for junk in (None, "", 42, {"x": 1}, "noseparators", " ¦  ¦ ", "k: ", ": v",
                 "PID: notanint", "k:v:w:x", "¦" * 50):
        d = D.parse_details(junk)
        assert isinstance(d, dict)
        D.pid(d); D.parentpid(d); D.user(d); D.hashes(d); D.tgtip(d)  # no raise


def test_colon_in_value_and_last_wins():
    d = D.parse_details("Url: http://x/y:8080/z ¦ PID: 1 ¦ PID: 2")
    assert d["url"] == "http://x/y:8080/z"
    assert D.pid(d) == "2"  # last wins


def test_against_real_fixture():
    import json
    fx = json.load(open("/app/services/fusion/fixtures/attack.json"))
    rows = fx["collected_data"]["Windows.Hayabusa.Rules"]
    parsed = [D.parse_details(r.get("Details")) for r in rows]
    # at least one EID-1-style row yields a pid + proc + hashes, proving real-data parse
    assert any(D.pid(p) and D.proc(p) and D.hashes(p) for p in parsed)
    assert any(D.tgtip(p) for p in parsed)  # at least one netconn


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
