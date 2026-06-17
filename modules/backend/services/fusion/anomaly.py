"""Per-row anomaly scoring. Reuses the memory module's ``_row_severity``
when importable; otherwise a self-contained fallback with the same weights
(so the fusion layer + its tests run with no memory-module dependency).
"""

from __future__ import annotations

_CRIT = ("page_execute_readwrite", "execute_writecopy", "execute_readwrite", "rwx")
_HIGH = ("powershell", "certutil", "rundll32", "regsvr32", "mshta", "wmic",
         "bitsadmin", "wscript", "cscript", "schtasks", "psexec", "mimikatz",
         "cobalt", "metasploit", "meterpreter", "rubeus", "sharphound",
         "\\temp\\", "\\appdata\\", "\\programdata\\", "\\public\\",
         "unsigned", "hidden", "inject", "hollow", "orphan", ".tmp")
_MED = ("established", "listening", "syn_sent")

try:  # prefer the real scorer for parity with memory analysis
    from services.memory.analyzers import _row_severity as _real  # type: ignore
except Exception:  # pragma: no cover - exercised when memory module absent
    _real = None


def score_row(row) -> int:
    if _real is not None:
        try:
            return int(_real(row))
        except Exception:
            pass
    if not isinstance(row, dict):
        return 0
    blob = " ".join(str(v) for v in row.values()).lower()
    s = 0
    for kw in _CRIT:
        if kw in blob:
            s += 100
    for kw in _HIGH:
        if kw in blob:
            s += 10
    for kw in _MED:
        if kw in blob:
            s += 1
    return s
