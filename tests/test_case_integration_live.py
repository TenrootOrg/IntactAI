"""Wrapper: run tests/live_case_integration.py inside the live backend container.

It drives a throwaway COPY of a real case (never the case itself) through every
analyst input and checks every output — Timeline, Risk, Identities, the no-LLM
report, and what the report and chat models are sent. See that file.

Skips unless docker, the backend container and a source case are available:
    INTACT_ITEST_CASE=<case_id> python3 tests/test_case_integration_live.py
    INTACT_ITEST_LLM=1 also runs one real chat answer and one real report.
Takes several minutes (each verdict re-fuses the copy).
"""
import os
import shutil
import subprocess
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
CONTAINER = os.environ.get("INTACT_BACKEND", "intact_backend")
CASE = os.environ.get("INTACT_ITEST_CASE")


def _container_up():
    if not shutil.which("docker"):
        return False
    r = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
                       capture_output=True, text=True)
    return r.stdout.strip() == "true"


class LiveCaseIntegration(unittest.TestCase):
    def test_every_input_reaches_every_output(self):
        if not CASE or not _container_up():
            self.skipTest("needs INTACT_ITEST_CASE and a running backend container")
        subprocess.run(["docker", "cp", os.path.join(HERE, "live_case_integration.py"),
                        f"{CONTAINER}:/tmp/live_case_integration.py"], check=True)
        cmd = ["docker", "exec", CONTAINER, "python3", "/tmp/live_case_integration.py", CASE]
        if os.environ.get("INTACT_ITEST_LLM"):
            cmd.append("--llm")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        out = "\n".join(ln for ln in r.stdout.splitlines() if not ln.startswith(("[STORAGE]", "[WORKFLOW]", "[GRPC]")))
        print(out)
        self.assertEqual(r.returncode, 0, out[-3000:] + r.stderr[-1500:])


if __name__ == "__main__":
    unittest.main()
