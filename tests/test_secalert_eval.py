"""scripts/dev/secalert_eval.py: the metrics are right, the sample repeats, and
the answer (the Label) never reaches the model. Pure functions only: no backend,
no dataset, no network."""
import importlib.util
import json
import os
import unittest

_P = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts", "dev", "secalert_eval.py")
_spec = importlib.util.spec_from_file_location("secalert_eval", _P)
E = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(E)

ALERT = {"rule_name": "SQL injection", "attack_type": "SQL", "method": "GET", "uri": "/a?id=1'",
         "rsp_status": 200, "host": "shop.example", "dip": "10.0.0.5", "sip": "1.2.3.4",
         "sport": 5555, "dport": 80, "parameter": "id=1'", "req_header": "GET /a", "req_body": "",
         "rsp_header": "HTTP/1.1 200", "rsp_body": "x" * 5000, "kill_chain_all": "exploit",
         "Label": "Attack"}


def ans(choice, p_tp=0.5, conf=0.5):
    return {"choice": choice, "probabilities": {"true_positive": p_tp}, "confidence": conf}


class AlertState(unittest.TestCase):
    def test_label_never_sent(self):
        text = json.dumps(E.alert_state(ALERT))
        self.assertNotIn("Label", text)
        self.assertNotIn("Non-Attack", text)

    def test_bodies_are_clipped(self):
        self.assertLessEqual(len(E.alert_state(ALERT)["evidence"]["response"]), E.CLIP)


class Sample(unittest.TestCase):
    def test_same_seed_same_alerts(self):
        rows = [{"n": i} for i in range(100)]
        self.assertEqual(E.sample(rows, 10, 7), E.sample(rows, 10, 7))
        self.assertNotEqual(E.sample(rows, 10, 7), E.sample(rows, 10, 8))
        self.assertEqual(len(E.sample(rows, 0, 7)), 100)


class Score(unittest.TestCase):
    def test_binary_metrics(self):
        pairs = [(True, ans("true_positive", 0.9, 0.9)),    # TP
                 (True, ans("false_positive", 0.2, 0.8)),   # FN
                 (False, ans("true_positive", 0.7, 0.6)),   # FP
                 (False, ans("known", 0.1, 0.9)),            # TN: known counts as not-attack
                 (False, None)]                              # no answer: excluded
        s = E.score(pairs, threshold=0.8)
        self.assertEqual((s["tp"], s["fn"], s["fp"], s["tn"]), (1, 1, 1, 1))
        self.assertEqual((s["asked"], s["answered"]), (5, 4))
        self.assertAlmostEqual(s["precision"], 0.5)
        self.assertAlmostEqual(s["recall"], 0.5)
        self.assertAlmostEqual(s["false_positive_rate"], 0.5)
        self.assertAlmostEqual(s["brier"], (0.01 + 0.64 + 0.49 + 0.01) / 4)
        self.assertEqual((s["chips_shown"], s["chips_right"]), (3, 2))
        # p(attack): attacks 0.9, 0.2; non-attacks 0.7, 0.1 -> 3 of 4 pairs ranked right
        self.assertAlmostEqual(s["auc"], 0.75)
        t90 = [row for row in s["sweep"] if abs(row[0] - 0.9) < 1e-9][0]
        self.assertEqual(t90[1:], [0.75, 0.0, 0.5])   # accuracy, FPR, recall at p >= 0.9

    def test_no_answers(self):
        self.assertEqual(E.score([(True, None)], 0.5), {"asked": 1, "answered": 0})


if __name__ == "__main__":
    unittest.main()
