"""UPGRADE_ORDER, read from the bash that actually applies it.

The order used to live in `services/upgrade/__init__.py`, so the CI packager
imported it from the backend. That import is why `build_release_package.py`
carried a 50-line stub that faked a `services` package in sys.modules: the
`resolve` job runs on a bare runner with only pyyaml + requests, and
`services/__init__.py` eagerly imports the whole service graph including grpc.

The engine is bash now and `lib/upgrade/plan.sh` is the only definition that
matters -- it is what the module loop iterates. Parsing it is not a workaround
for the import; it is reading the single source of truth. A second copy here
would be a list that can silently disagree with the one doing the work, and
disagreement means a release that ships an asset nothing applies (or omits one
something expects).

Zero dependencies on purpose: this must answer "what would this build?" before
any container exists.
"""

import os
import re

_DECL = re.compile(r'^UPGRADE_ORDER=\(([^)]*)\)', re.MULTILINE)


def repo_root() -> str:
    """The checkout root, from INTACT_PATH or this file's location.

    INTACT_PATH first because the packager container mounts the checkout at an
    arbitrary path and bakes its own copy of the backend at /app -- walking up
    from __file__ inside the container would find the wrong tree.
    """
    env = os.environ.get('INTACT_PATH')
    if env and os.path.isfile(os.path.join(env, 'lib', 'upgrade', 'plan.sh')):
        return env
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..', '..'))


def upgrade_order(root: str = None):
    """The module ids, in the order upgrade.sh applies them."""
    path = os.path.join(root or repo_root(), 'lib', 'upgrade', 'plan.sh')
    try:
        with open(path, encoding='utf-8') as fh:
            text = fh.read()
    except OSError as e:
        raise RuntimeError(
            f"cannot read {path} to determine UPGRADE_ORDER ({e}). "
            f"Set INTACT_PATH to the checkout root.") from e

    m = _DECL.search(text)
    if not m:
        raise RuntimeError(
            f"no `UPGRADE_ORDER=(...)` declaration in {path} -- the packager "
            f"and the upgrader would disagree about what a release contains.")

    # Bash word-splitting, minus the quoting nobody uses in this declaration.
    order = [w for w in m.group(1).split() if w and not w.startswith('#')]
    if not order:
        raise RuntimeError(f"UPGRADE_ORDER in {path} is empty")
    return order
