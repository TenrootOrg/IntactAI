"""The AI-call ledger: one row per model call, what it cost, which case it was for.

WHY. Until 2026-11-22 a call's cost was only added to a running total on the run
(workflow_service.record_llm_metrics), so nobody could see what a case had cost,
or which call cost what, and no case could be held to a budget. Every call now
lands here (services/agentic/analyzers/_llm.py and the decision model), and a
case's cost and budget are sums over its rows.

The cost is EXACT when the provider says what it charged (OpenRouter returns it
per call, usage.cost); otherwise tokens x the price list ("estimated"), $0 for a
local model, and "subscription" for a vendor CLI login (no per-call price).

Nothing here may break an AI call: recording swallows its own errors. Only the
budget check raises, on purpose, before the call is made.
"""
import datetime as _dt

from services.storage.base import get_connection

SOURCE_CASE_DEFAULT = "case analysis"
SOURCE_RUN_DEFAULT = "agentic run"


class AIBudgetExceeded(RuntimeError):
    """A case's AI budget is used up: no new model call for it."""

    reason = "case_budget"      # llm_sim keeps a known reason code (its messages table)

    def __init__(self, case_id, budget, spent):
        self.case_id, self.budget, self.spent = case_id, budget, spent
        super().__init__(f"This case reached its AI budget (${budget:,.2f}; "
                         f"${spent:,.2f} spent). Raise it in the case's Configuration.")


def case_of(run_id):
    """The case a run id belongs to: a case id is its own case; an agentic run
    carries its case in workflows.case_id. None when there is none."""
    if not run_id:
        return None
    run_id = str(run_id)
    if run_id.startswith("case_"):
        return run_id
    try:
        row = get_connection().execute(
            "SELECT case_id FROM workflows WHERE run_id = ?", (run_id,)).fetchone()
        return (row[0] or None) if row else None
    except Exception:                                   # noqa: BLE001
        return None


def record(run_id, *, provider, model, input_tokens=0, output_tokens=0,
           cost_usd=0.0, cost_kind="estimated", source=None, case_id=None):
    """One ledger row. Never raises: a failed write must not fail the AI call."""
    try:
        cid = case_id or case_of(run_id)
        if not source:
            source = SOURCE_CASE_DEFAULT if (run_id and str(run_id) == cid) else SOURCE_RUN_DEFAULT
        conn = get_connection()
        conn.execute(
            "INSERT INTO llm_usage (ts, case_id, run_id, source, provider, model, input_tokens,"
            " output_tokens, cost_usd, cost_kind) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (_dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), cid,
             str(run_id) if run_id else None, source, provider or "", model or "",
             int(input_tokens or 0), int(output_tokens or 0), float(cost_usd or 0.0),
             cost_kind or "estimated"))
        conn.commit()
    except Exception as ex:                             # noqa: BLE001
        print(f"[LLM-USAGE] could not record a call: {ex}", flush=True)


def case_spent(case_id) -> float:
    try:
        row = get_connection().execute(
            "SELECT COALESCE(SUM(cost_usd), 0) FROM llm_usage WHERE case_id = ?",
            (case_id,)).fetchone()
        return float(row[0] or 0.0)
    except Exception:                                   # noqa: BLE001
        return 0.0


def case_summary(case_id) -> dict:
    """What a case's AI calls cost: total, how much of it is estimated, and the
    split by source and by model, with the date the counting began."""
    out = {"calls": 0, "input_tokens": 0, "output_tokens": 0, "cost_usd": 0.0,
           "estimated_usd": 0.0, "since": None, "by_source": [], "by_model": []}
    try:
        conn = get_connection()
        r = conn.execute(
            "SELECT COUNT(*), COALESCE(SUM(input_tokens),0), COALESCE(SUM(output_tokens),0),"
            " COALESCE(SUM(cost_usd),0),"
            " COALESCE(SUM(CASE WHEN cost_kind='estimated' THEN cost_usd ELSE 0 END),0), MIN(ts)"
            " FROM llm_usage WHERE case_id = ?", (case_id,)).fetchone()
        out.update(calls=int(r[0]), input_tokens=int(r[1]), output_tokens=int(r[2]),
                   cost_usd=round(float(r[3]), 6), estimated_usd=round(float(r[4]), 6), since=r[5])
        for col, key in (("source", "by_source"), ("model", "by_model")):
            out[key] = [{"name": n or "(unknown)", "calls": int(c), "cost_usd": round(float(u), 6)}
                        for n, c, u in conn.execute(
                            f"SELECT {col}, COUNT(*), COALESCE(SUM(cost_usd),0) FROM llm_usage"
                            f" WHERE case_id = ? GROUP BY {col} ORDER BY 3 DESC, 2 DESC", (case_id,))]
    except Exception as ex:                             # noqa: BLE001
        print(f"[LLM-USAGE] summary failed for {case_id}: {ex}", flush=True)
    return out


def _budget_value(v):
    try:
        f = float(v)
        return f if f > 0 else None
    except (TypeError, ValueError):
        return None


def default_budget():
    """Settings -> Agentic: the AI budget a case gets when it has none of its own."""
    try:
        from services.memory.pipeline import _llm_config_from_runtime
        return _budget_value(((_llm_config_from_runtime() or {}).get("agentic") or {})
                             .get("case_ai_budget_default_usd"))
    except Exception:                                   # noqa: BLE001
        return None


def case_budget(case_id):
    """(budget in USD or None for no limit, 'case' | 'default' | None)."""
    own = None
    try:
        from services.fusion import store
        own = _budget_value(((store.get_case(case_id) or {}).get("ai_budget_usd")))
    except Exception:                                   # noqa: BLE001
        pass
    if own is not None:
        return own, "case"
    d = default_budget()
    return (d, "default") if d is not None else (None, None)


def check_budget(run_id):
    """Raise AIBudgetExceeded when the case this call is for has used up its AI
    budget. A call for no case, or a case without a budget, always passes. Asked
    BEFORE the call: a call's price is only known after its answer, so the last
    call may go a little over."""
    cid = case_of(run_id)
    if not cid:
        return
    budget, _src = case_budget(cid)
    if budget is None:
        return
    spent = case_spent(cid)
    if spent >= budget:
        raise AIBudgetExceeded(cid, budget, spent)
