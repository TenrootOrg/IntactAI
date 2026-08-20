"""Every workflow step must be a shape GitHub Actions will accept.

Parsing a workflow as YAML proves almost nothing. A step is a mapping, and YAML
will accept any keys you put in it -- so moving a `- uses:` line without the
`with:` block underneath it silently reparents that block onto whatever step now
precedes it, and the file still loads cleanly. That is exactly what happened
here: `actions/checkout` was moved above the input validator, its `with:` stayed
behind, and the validator became a step with both `run:` and `with:`. Actions
rejects that at parse time, so the run failed with ZERO jobs -- no logs, no
annotations, nothing to read -- and a local yaml.safe_load had reported the job
as a healthy nineteen steps.

These are the structural rules Actions enforces and YAML does not.
"""

import glob
import os
import unittest

try:
    import yaml
except ImportError:                                           # pragma: no cover
    yaml = None

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOWS = sorted(glob.glob(os.path.join(ROOT, ".github/workflows/*.yml"))
                   + glob.glob(os.path.join(ROOT, ".github/workflows/*.yaml")))


def step_problems(job_name, steps):
    """Rules Actions enforces on a step that YAML does not."""
    out = []
    for i, step in enumerate(steps or []):
        where = f"{job_name}[{i}] {step.get('name') or step.get('uses') or '?'}"
        if not isinstance(step, dict):
            out.append(f"{where}: step is not a mapping")
            continue
        has_run, has_uses = "run" in step, "uses" in step
        if has_run and has_uses:
            out.append(f"{where}: has both `run` and `uses`")
        elif not has_run and not has_uses:
            out.append(f"{where}: has neither `run` nor `uses`")
        if "with" in step and not has_uses:
            out.append(f"{where}: has `with` but no `uses` — an orphaned "
                       f"`with:` block reparented onto a `run:` step is the "
                       f"classic result of moving a step by hand")
        if "run" in step and "shell" not in step and not isinstance(
                step["run"], str):
            out.append(f"{where}: `run` is not a string")
    return out


@unittest.skipIf(yaml is None, "PyYAML not installed")
class TestWorkflowShape(unittest.TestCase):

    def test_there_are_workflows_to_check(self):
        self.assertTrue(WORKFLOWS, "no workflow files found — wrong path?")

    def test_every_step_is_a_shape_actions_accepts(self):
        problems = []
        for path in WORKFLOWS:
            with open(path, encoding="utf-8") as fh:
                doc = yaml.safe_load(fh)
            rel = os.path.relpath(path, ROOT)
            for job_name, job in (doc.get("jobs") or {}).items():
                if not isinstance(job, dict):
                    problems.append(f"{rel}: job {job_name} is not a mapping")
                    continue
                if "uses" in job:
                    continue                    # a reusable-workflow call
                if "runs-on" not in job:
                    problems.append(f"{rel}: job {job_name} has no runs-on")
                problems += [f"{rel}: {p}" for p
                             in step_problems(job_name, job.get("steps"))]
        self.assertFalse(problems, "workflow steps Actions will reject:\n  "
                         + "\n  ".join(problems))

    def test_the_checker_catches_an_orphaned_with(self):
        """Non-vacuous, in the exact shape of the bug that caused it."""
        broken = yaml.safe_load(
            "steps:\n"
            "  - name: Validate\n"
            "    run: echo hi\n"
            "    with:\n"
            "      ref: main\n")
        problems = step_problems("e2e", broken["steps"])
        self.assertTrue(any("`with` but no `uses`" in p for p in problems),
                        problems)

    def test_the_checker_accepts_a_normal_pair(self):
        fine = yaml.safe_load(
            "steps:\n"
            "  - uses: actions/checkout@v4\n"
            "    with:\n"
            "      ref: main\n"
            "  - name: Build\n"
            "    run: make\n")
        self.assertEqual(step_problems("e2e", fine["steps"]), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
