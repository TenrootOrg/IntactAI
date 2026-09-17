"""An air-gapped appliance must not say it is calling a model it cannot reach.

QA TASK-12656 ("airgapped vm, why saying llm?"): Regenerate on a VM with no
internet showed "Sending case data to the model" and waited out a connection
timeout. provider_route() is now asked first -- a bounded TCP connect, no
tokens -- and a failed route writes the report offline and says so.
"""

import os
import socket
import sys
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _p in (os.path.dirname(os.path.abspath(__file__)),
           os.path.join(ROOT, "modules", "backend")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import _optional_deps  # noqa: F401,E402

from services.fusion import llm_sim  # noqa: E402


def _offline_cfg(url):
    return {"llm_mode": "offline", "offline_llm": {"provider": "ollama", "url": url, "model": "m"}}


class ProviderRoute(unittest.TestCase):
    def test_closed_port_is_no_route_and_fast(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); port = s.getsockname()[1]; s.close()
        with mock.patch.object(llm_sim, "_agentic_cfg", return_value=_offline_cfg(f"http://127.0.0.1:{port}")):
            t = time.time()
            r = llm_sim.provider_route(timeout=1.0)
        self.assertFalse(r["ok"])
        self.assertEqual(r["code"], "no_internet")
        self.assertLess(time.time() - t, 2.0)

    def test_blackholed_host_is_bounded_by_timeout(self):
        with mock.patch.object(llm_sim, "_agentic_cfg", return_value=_offline_cfg("http://10.255.255.1:11434")):
            t = time.time()
            r = llm_sim.provider_route(timeout=1.0)
        self.assertFalse(r["ok"])
        self.assertLess(time.time() - t, 2.0)

    def test_listening_endpoint_is_ok(self):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(1)
        try:
            url = f"http://127.0.0.1:{s.getsockname()[1]}"
            with mock.patch.object(llm_sim, "_agentic_cfg", return_value=_offline_cfg(url)):
                self.assertTrue(llm_sim.provider_route(timeout=1.0)["ok"])
        finally:
            s.close()

    def test_proxy_or_unknown_provider_is_left_to_the_real_call(self):
        cfg = {"llm_mode": "online", "online_llm": {"provider": "no-such", "api_key": "k"}}
        with mock.patch.object(llm_sim, "_agentic_cfg", return_value=cfg):
            self.assertTrue(llm_sim.provider_route()["ok"])
        cfg["online_llm"]["provider"] = "openrouter"
        with mock.patch.object(llm_sim, "_agentic_cfg", return_value=cfg), \
             mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy:3128"}):
            self.assertTrue(llm_sim.provider_route()["ok"])


class OfflineTag(unittest.TestCase):
    def test_replaces_the_generic_note_with_the_reason(self):
        from services.fusion import store
        route = {"reason": "The appliance cannot reach the AI provider.",
                 "fix": "Check the appliance's internet connection, then try again."}
        md = "# R\n\nbody" + "\n\n---\n_Deterministic report — AI model was not used._\n"
        out = store._offline_tag(md, route)
        self.assertEqual(out.count("_Deterministic report — "), 1)
        self.assertTrue(out.endswith("then try again._\n"))
        self.assertIn("cannot reach the AI provider", out)


if __name__ == "__main__":
    unittest.main()


class ReachabilityIsFastWithNoRoute(unittest.TestCase):
    """QA TASK-12664: the live check used to wait out the model call's timeout on an
    air-gapped box, and the page meanwhile claimed "connected" from config."""

    def test_no_route_answers_without_calling_the_model(self):
        cfg = {"llm_mode": "online", "online_llm": {"provider": "openrouter", "api_key": "k", "model": "m"}}
        llm_sim._REACH_CACHE.clear()
        with mock.patch.object(llm_sim, "_agentic_cfg", return_value=cfg), \
             mock.patch.object(llm_sim, "provider_route", return_value={"ok": False, "code": "no_internet"}), \
             mock.patch("services.agentic.analyzers._llm.call_llm") as call:
            r = llm_sim.llm_reachability()
        self.assertFalse(r["available"])
        self.assertEqual(r["code"], "no_internet")
        self.assertTrue(r["checked_live"])
        call.assert_not_called()
