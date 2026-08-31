# Track A — Agentic fault-injection (deterministic)

4 findings / 8 scenarios. No real model.

| Sev | ID | Status | Finding | Repro |
|---|---|---|---|---|
| high | A1 | FINDING | turn-1 {final} give-up with 0 tool calls is not caught/retried | model emits {"final":...} on iteration 0 |
| high | A2 | FINDING | tool exception propagates out of investigate() -> HTTP 500 | tool raises (bad limit / malformed pivot.window) |
| high | A3 | FINDING | transport failure propagates -> unhandled 500 (report path catches it) | _real_llm raises |
| medium | A7b | FINDING | forced-final can return raw model text as the analyst answer | model never returns {final}, even on the forced call |
| medium | A7a | PASS | malformed-JSON storm burns budget without a separate retry counter | model never emits valid JSON |
| medium | A6c | PASS | empty/None model completion degrades to malformed (no crash) | transport returns an empty string |
| low | A11 | PASS | non-final object with no 'tool' key -> bogus 'unknown tool None' step | model returns an object with neither 'tool' nor 'final' |
| info | A_unknown | PASS | unknown tool name is handled (error fed back, not fatal) | model calls a tool that doesn't exist |

## Detail

- **[high] A1 — turn-1 {final} give-up with 0 tool calls is not caught/retried**  
  raised=False steps=0 answer='I could not find anything.' — the loop accepted a 0-tool final; nothing forces a lookup or retries.
- **[high] A2 — tool exception propagates out of investigate() -> HTTP 500**  
  raised=True (simulated tool crash (e.g. int('abc') on limit)) — _tool() has no try/except; model-controlled args can crash the request.
- **[high] A3 — transport failure propagates -> unhandled 500 (report path catches it)**  
  raised=True (_Boom) — investigate does not catch LLMUnavailable like store.chat/report do.
- **[medium] A7b — forced-final can return raw model text as the analyst answer**  
  answer='{"tool":"list_findings","args":{}}' — after budget, obj.get('final') or raw; a non-final raw blob becomes the answer.
