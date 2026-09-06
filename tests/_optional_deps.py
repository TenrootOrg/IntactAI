"""Satisfy the heavy optional imports `services/__init__.py` drags in.

WHY THIS EXISTS. Importing anything under `services.` executes
`services/__init__.py`, which imports `velociraptor_service`, which does
`import grpc`. grpc is a backend-container dependency, not a test one, and
tests/run_tests.sh deliberately runs on "plain bash + stdlib python3, nothing to
install" -- so three suites died at import with ModuleNotFoundError the moment
the test workflow's push trigger was restored. They had been failing that way
for weeks; nothing ran them, so nobody knew.

Under pytest they pass, because some earlier test in the same process has
already stubbed grpc. Run standalone -- which is exactly what run_tests.sh does
-- they do not. A suite whose result depends on what ran before it is not
telling you anything.

Stubs are permissive on purpose: these tests never call grpc, they only need the
import to succeed. Anything genuinely exercising a stubbed module would get an
attribute that does nothing and should be stubbing it deliberately itself.
"""

import sys
import types


class _Anything(types.ModuleType):
    """A module that answers any attribute with another one of itself."""

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        child = _Anything(f"{self.__name__}.{name}")
        setattr(self, name, child)
        return child

    def __call__(self, *_a, **_k):
        return self


def stub(*names):
    """Insert a permissive stub for each module that is not importable."""
    stubbed = []
    for name in names:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = _Anything(name)
            stubbed.append(name)
    return stubbed


# The set the backend imports at module scope and these tests never touch.
MISSING = stub("grpc", "pyvelociraptor")
