"""Memory mapper dedups processes by (PID, createtime).

pslist/psscan/pstree each enumerate the same processes, so the old per-row
append produced 2-3x duplicate process entities (a real run showed 358 entities
for 157 processes). The mapper now emits ONE entity per real process while
preserving the signals that matter:
  * a process seen ONLY by psscan (unlinked/terminated) is flagged `hidden`;
  * genuine PID reuse (one PID, two different createtimes) stays split so two
    distinct processes never merge;
  * malfind injection lands on the single deduped entity, not a duplicate.

Regression guard for services/fusion/mappers/memory.py.
"""

import sys
if "/app" not in sys.path:
    sys.path.insert(0, "/app")

from services.fusion.mappers.memory import map_memory  # noqa: E402

_A = "asset:endpoint:C.test"
_T1 = "2026-06-01T09:00:00"
_T2 = "2026-06-20T18:00:00"


def _payload(plugins, yara=None):
    return {"plugins": plugins, "yara": yara or [], "host": "HOST-1"}


def _procs(ents):
    return [e for e in ents if e.type == "process"]


def test_same_process_across_plugins_dedups_to_one():
    # PID 100 listed by all three process plugins (psscan/pstree commonly lack a
    # createtime in Vol3 output) collapses to ONE entity.
    plugins = {
        "windows.pslist.PsList": [{"PID": 100, "ImageFileName": "svchost.exe", "CreateTime": _T1}],
        "windows.psscan.PsScan": [{"PID": 100, "ImageFileName": "svchost.exe"}],
        "windows.pstree.PsTree": [{"PID": 100, "ImageFileName": "svchost.exe"}],
    }
    ents, _ = map_memory(_payload(plugins), run_id="r1", asset=_A)
    procs = _procs(ents)
    assert len(procs) == 1, f"expected 1 deduped process, got {len(procs)}"
    assert procs[0].attrs.get("seen_by") == ["pslist", "psscan", "pstree"]


def test_psscan_only_process_is_flagged_hidden():
    # A process pslist never listed but psscan found = unlinked/terminated = hidden.
    plugins = {
        "windows.pslist.PsList": [{"PID": 100, "ImageFileName": "svchost.exe", "CreateTime": _T1}],
        "windows.psscan.PsScan": [{"PID": 666, "ImageFileName": "evil.exe"}],
    }
    ents, _ = map_memory(_payload(plugins), run_id="r1", asset=_A)
    hidden = [e for e in _procs(ents) if "hidden" in (e.flags or [])]
    assert len(hidden) == 1, "psscan-only process must be flagged hidden"
    assert hidden[0].attrs.get("pid") == "666"
    # the pslist process must NOT be flagged hidden
    visible = [e for e in _procs(ents) if e.attrs.get("pid") == "100"]
    assert visible and "hidden" not in (visible[0].flags or [])


def test_pid_reuse_with_distinct_createtimes_stays_split():
    # Same PID, two genuinely different createtimes = a dead proc + a live one.
    # They must NOT merge into one entity.
    plugins = {
        "windows.pslist.PsList": [{"PID": 100, "ImageFileName": "new.exe", "CreateTime": _T2}],
        "windows.psscan.PsScan": [{"PID": 100, "ImageFileName": "old.exe", "CreateTime": _T1}],
    }
    ents, _ = map_memory(_payload(plugins), run_id="r1", asset=_A)
    assert len(_procs(ents)) == 2, "PID reuse (distinct createtimes) must stay split"


def test_injection_not_duplicated_and_flagged():
    # malfind on a PID already seen by pslist/psscan marks that ONE entity injected.
    plugins = {
        "windows.pslist.PsList": [{"PID": 100, "ImageFileName": "powershell.exe", "CreateTime": _T1}],
        "windows.psscan.PsScan": [{"PID": 100, "ImageFileName": "powershell.exe"}],
        "windows.malfind.Malfind": [
            {"PID": 100, "Process": "powershell.exe", "Protection": "PAGE_EXECUTE_READWRITE"},
            {"PID": 100, "Process": "powershell.exe", "Protection": "PAGE_EXECUTE_READWRITE"},
        ],
    }
    ents, _ = map_memory(_payload(plugins), run_id="r1", asset=_A)
    procs = _procs(ents)
    assert len(procs) == 1, "injected process must not be duplicated by malfind"
    assert "injected" in (procs[0].flags or [])
    assert procs[0].anomaly >= 100


def test_yara_hit_links_to_its_process_once():
    plugins = {"windows.pslist.PsList": [{"PID": 100, "ImageFileName": "evil.exe", "CreateTime": _T1}]}
    yara = [{"rule": "HKTL_X", "pid": 100}]
    ents, rels = map_memory(_payload(plugins, yara), run_id="r1", asset=_A)
    yh = [e for e in ents if e.type == "yarahit"]
    assert len(yh) == 1, "one yara hit -> one yarahit entity"
    proc_id = _procs(ents)[0].id
    matched = [r for r in rels if r.kind == "matched"]
    assert any(proc_id in (r.src, r.dst) for r in matched), "yarahit must link to its process"


def test_dedup_is_deterministic_and_complete():
    plugins = {
        "windows.pslist.PsList": [
            {"PID": i, "ImageFileName": f"p{i}.exe", "CreateTime": _T1} for i in range(20)
        ],
        "windows.psscan.PsScan": [{"PID": i, "ImageFileName": f"p{i}.exe"} for i in range(20)],
    }
    a, _ = map_memory(_payload(plugins), run_id="r1", asset=_A)
    b, _ = map_memory(_payload(plugins), run_id="r1", asset=_A)
    assert sorted(e.id for e in a) == sorted(e.id for e in b), "dedup must be deterministic"
    assert len(_procs(a)) == 20, "20 distinct PIDs -> 20 process entities (no dupes, none lost)"
