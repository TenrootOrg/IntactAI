#!/usr/bin/env python3
"""How good is the decision model's suggested verdict on THIRD-PARTY alerts?

decision_eval.py measures the verdict chip on findings analysts judged on this
box -- our own data, and usually little of it. This measures the same question
on SecAlertBench (github.com/Dxsssu/SecAlertBench): 8,322 real network IDS/WAF
alerts from three enterprise SOCs, each labelled Attack / Non-Attack.

Same production path: each alert is turned into the state shape
decision_model.finding_state() builds for a finding, and asked
decision_model._verdict_question through decision_model.ask_each -- the model,
batching and settings the live chip uses. The model's `true_positive` counts as
"attack"; `known` and `false_positive` both count as "not attack".

A fixed seed picks the sample, so every run asks about the same alerts and two
runs (or two versions of the code) are comparable. Each run's answers are saved
under /app/data/secalert-eval/ for that comparison.

The dataset has NO LICENCE: internal measurement only. It is passed in with
--data and must never be committed or bundled. The alerts are public with
randomised IPs, so they are sent unmasked (there is no case to mask against).
Needs the decision model enabled (Settings -> Agentic, with its provider key).

    docker cp secalertbench.json intact_backend:/tmp/secalertbench.json
    docker cp scripts/dev/secalert_eval.py intact_backend:/tmp/secalert_eval.py
    docker exec intact_backend sh -lc 'cd /app && python3 /tmp/secalert_eval.py \
        --data /tmp/secalertbench.json [--sample 400] [--seed 20261112]'
"""
import argparse
import json
import os
import random
import sys
import time

CLIP = 1500  # chars per request/response part: a long body is noise, and tokens


def alert_state(a: dict) -> dict:
    """One alert in finding_state()'s shape. Severity is left out on purpose, as
    decision_eval does, and the label fields never reach the model."""
    req = (a.get("req_header") or "") + (a.get("req_body") or "")
    rsp = (a.get("rsp_header") or "") + (a.get("rsp_body") or "")
    return {
        "title": a.get("rule_name") or "",
        "summary": f'{a.get("method", "")} {a.get("uri", "")} -> HTTP {a.get("rsp_status", "")} '
                   f'(attack type per the rule: {a.get("attack_type", "")}; '
                   f'kill-chain stage: {a.get("kill_chain_all", "")})',
        "detected_by": ["network IDS/WAF"],
        "hosts": [h for h in (a.get("host"), a.get("dip")) if h],
        "mitre": [],
        "evidence": {
            "source": f'{a.get("sip", "")}:{a.get("sport", "")}',
            "destination": f'{a.get("dip", "")}:{a.get("dport", "")}',
            "parameter": (a.get("parameter") or "")[:CLIP],
            "request": req[:CLIP],
            "response": rsp[:CLIP],
        },
    }


def sample(rows: list, n: int, seed: int) -> list:
    """(index, alert) pairs, the same ones every time for the same rows/n/seed."""
    idx = list(range(len(rows)))
    random.Random(seed).shuffle(idx)
    return [(i, rows[i]) for i in sorted(idx[:n] if n else idx)]


def as_shown(dm, ans):
    """The answer with `choice` replaced by the label production's chip shows
    (decision_model._answer_to_suggestion), so the eval measures the chip, not the raw pick."""
    if not isinstance(ans, dict):
        return ans
    return dict(ans, choice=(dm._answer_to_suggestion(ans) or {}).get("label"))


def score(pairs: list, threshold: float) -> dict:
    """pairs: (is_attack, answer-dict-or-None). Binary metrics for 'attack', over the
    answers that got a label; `whole` counts every answered item, including those the
    chip leaves unlabelled (choice None: the uncertain band), which is what a person sees."""
    answered = [(y, a) for y, a in pairs if isinstance(a, dict)]
    ok = [(y, a) for y, a in answered if a.get("choice")]
    out = {"asked": len(pairs), "answered": len(ok)}
    n_att = sum(1 for y, _ in answered if y)
    out["whole"] = {
        "answered": len(answered), "no_label": len(answered) - len(ok),
        "non_attacks_called_attack": [sum(1 for y, a in ok if not y and a["choice"] == "true_positive"),
                                      len(answered) - n_att],
        "attacks_called_attack": [sum(1 for y, a in ok if y and a["choice"] == "true_positive"), n_att],
        "attacks_called_benign": [sum(1 for y, a in ok if y and a["choice"] != "true_positive"), n_att],
    }
    if not ok:
        return out
    tp = sum(1 for y, a in ok if y and a["choice"] == "true_positive")
    fp = sum(1 for y, a in ok if not y and a["choice"] == "true_positive")
    fn = sum(1 for y, a in ok if y and a["choice"] != "true_positive")
    tn = len(ok) - tp - fp - fn
    p_att = [float((a.get("probabilities") or {}).get("true_positive", 0.0)) for _, a in ok]
    out.update(
        tp=tp, fp=fp, fn=fn, tn=tn,
        accuracy=(tp + tn) / len(ok),
        precision=tp / (tp + fp) if tp + fp else None,
        recall=tp / (tp + fn) if tp + fn else None,
        false_positive_rate=fp / (fp + tn) if fp + tn else None,
        brier=sum((p - (1.0 if y else 0.0)) ** 2 for p, (y, _) in zip(p_att, ok)) / len(ok),
    )
    bins = {}
    for y, a in ok:
        c = float(a.get("confidence") or 0.0)
        bins.setdefault(min(int(c * 10), 9), []).append((a["choice"] == "true_positive") == y)
    out["reliability"] = {f"{b / 10:.1f}-{(b + 1) / 10:.1f}": [sum(h), len(h)] for b, h in sorted(bins.items())}
    # Ranking quality of p(attack), apart from the choice. 2026-11-12: the choice was
    # "attack" for 379/400 (92% FPR) while p(attack) still ranked them at AUC 0.87 --
    # the signal is in the probabilities, so measure them on their own.
    pos = [p for p, (y, _) in zip(p_att, ok) if y]
    neg = [p for p, (y, _) in zip(p_att, ok) if not y]
    out["auc"] = (sum((p > q) + 0.5 * (p == q) for p in pos for q in neg) / (len(pos) * len(neg))
                  if pos and neg else None)
    out["sweep"] = [[t / 100, sum((p >= t / 100) == y for p, (y, _) in zip(p_att, ok)) / len(ok),
                     sum(1 for q in neg if q >= t / 100) / len(neg) if neg else None,
                     sum(1 for p in pos if p >= t / 100) / len(pos) if pos else None]
                    for t in range(50, 100, 5)]
    shown = [(y, a) for y, a in ok if float(a.get("confidence") or 0) >= threshold]
    out["threshold"] = threshold
    out["chips_shown"] = len(shown)
    out["chips_right"] = sum(1 for y, a in shown if (a["choice"] == "true_positive") == y)
    return out


def report(s: dict) -> str:
    pct = lambda v: "n/a" if v is None else f"{v:.0%}"  # noqa: E731
    lines = [f'{s["answered"]}/{s["asked"]} alerts got a label']
    w = s.get("whole")
    if w:
        frac = lambda p: f"{p[0]}/{p[1]} ({pct(p[0] / p[1]) if p[1] else 'n/a'})"  # noqa: E731
        lines += [f'  over everything answered ({w["answered"]}, {w["no_label"]} left without a label):',
                  f'    non-attacks labelled attack  {frac(w["non_attacks_called_attack"])}',
                  f'    attacks labelled attack      {frac(w["attacks_called_attack"])}',
                  f'    attacks labelled benign      {frac(w["attacks_called_benign"])}',
                  "  among the labelled ones:"]
    if s["answered"]:
        lines += [
            f'  attack caught (recall)       {pct(s["recall"])}   ({s["tp"]} of {s["tp"] + s["fn"]})',
            f'  "attack" calls right (prec.)  {pct(s["precision"])}   ({s["tp"]} of {s["tp"] + s["fp"]})',
            f'  false-positive rate          {pct(s["false_positive_rate"])}   ({s["fp"]} of {s["fp"] + s["tn"]} non-attacks called attack)',
            f'  accuracy {pct(s["accuracy"])}   Brier {s["brier"]:.3f} (0 perfect, 0.25 = always 50%)',
            "  reliability (stated confidence -> right / total):",
        ]
        lines += [f"    {b}: {r}/{n} ({r / n:.0%})" for b, (r, n) in s["reliability"].items()]
        if s["chips_shown"]:
            lines.append(f'  at the Settings threshold ({s["threshold"]}): {s["chips_shown"]} chips, '
                         f'{s["chips_right"] / s["chips_shown"]:.0%} right')
        if s.get("auc") is not None:
            lines.append(f'  ranking: AUC of p(attack) {s["auc"]:.2f} (0.5 = random, 1 = perfect)')
            lines.append("  if 'attack' meant p(attack) >= t:")
            lines += [f"    t={t:.2f}  accuracy {pct(a)}  FPR {pct(f)}  recall {pct(r)}" for t, a, f, r in s["sweep"]]
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", required=True, help="secalertbench.json (never commit it)")
    ap.add_argument("--sample", type=int, default=400, help="alerts to ask about; 0 = all 8,322")
    ap.add_argument("--seed", type=int, default=20261112)
    ap.add_argument("--out", default="/app/data/secalert-eval")
    a = ap.parse_args()

    sys.path.insert(0, "/app")
    from services.fusion import decision_model as dm  # noqa: E402

    if not dm.enabled("disposition"):
        sys.exit("The decision model is off: enable it (and 'Suggested verdict') in Settings -> Agentic.")
    rows = json.load(open(a.data, encoding="utf-8"))
    picked = sample(rows, a.sample, a.seed)
    n_att = sum(1 for _, r in picked if r.get("Label") == "Attack")
    print(f"{len(picked)} alerts (seed {a.seed}): {n_att} attack, {len(picked) - n_att} non-attack")

    t0 = time.time()
    answers = dm.ask_each([r for _, r in picked], lambda r: json.dumps(alert_state(r), ensure_ascii=False),
                          dm._verdict_question)
    secs = time.time() - t0
    s = score([(r.get("Label") == "Attack", as_shown(dm, ans)) for (_, r), ans in zip(picked, answers)],
              dm.min_confidence())
    s["seconds"] = round(secs, 1)
    print(report(s))
    print(f"  {secs:.0f}s")

    os.makedirs(a.out, exist_ok=True)
    path = os.path.join(a.out, time.strftime("%Y%m%d-%H%M%S") + f"-seed{a.seed}-n{len(picked)}.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"summary": s, "answers": [{"i": i, "label": r.get("Label"), "answer": ans}
                                               for (i, r), ans in zip(picked, answers)]}, fh)
    print(f"saved {path}")


if __name__ == "__main__":
    main()
