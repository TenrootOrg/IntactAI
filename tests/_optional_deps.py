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

import importlib.util
import sys
import types


class _Anything(types.ModuleType):
    """A module that answers any attribute with another one of itself."""

    # Marks the stub as a PACKAGE. Without it, `import apscheduler.schedulers`
    # fails at the parent lookup with "'apscheduler' is not a package" before
    # sys.meta_path is ever consulted, so _SubmoduleFinder never gets a turn.
    __path__ = []

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        child = _Anything(f"{self.__name__}.{name}")
        setattr(self, name, child)
        return child

    def __call__(self, *_a, **_k):
        return self


_STUBBED_ROOTS = set()


class _SubmoduleFinder:
    """Resolve any submodule of a stubbed root to another permissive stub.

    Without this, `import grpc` succeeds while `from apscheduler.schedulers.background
    import BackgroundScheduler` still raises: Python looks the dotted name up in
    sys.modules and asks the parent for a __path__, and a bare ModuleType has
    neither. Stubbing every dotted spelling by hand is the alternative, and it
    rots the moment the backend imports one more submodule.

    Appended to sys.meta_path, never prepended, so a genuinely installed package
    always wins over a stub of the same name.
    """

    @staticmethod
    def find_spec(name, path=None, target=None):
        if name.split(".")[0] not in _STUBBED_ROOTS:
            return None
        return importlib.util.spec_from_loader(name, _SubmoduleLoader())


class _SubmoduleLoader:
    @staticmethod
    def create_module(spec):
        return _Anything(spec.name)

    @staticmethod
    def exec_module(module):
        pass


def stub(*names):
    """Insert a permissive stub for each module that is not importable."""
    stubbed = []
    for name in names:
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = _Anything(name)
            _STUBBED_ROOTS.add(name)
            stubbed.append(name)
    if stubbed and _SubmoduleFinder not in sys.meta_path:
        sys.meta_path.append(_SubmoduleFinder)
    return stubbed


# The set the backend imports at module scope and these tests never touch.
MISSING = stub("grpc", "pyvelociraptor")
