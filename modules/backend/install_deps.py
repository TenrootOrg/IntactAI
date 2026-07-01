"""Install ALL module dependencies, regardless of which modules are
enabled in config.yaml.

Why unconditional:
    The original design conditionally installed `requirements-<module>.txt`
    only for modules where `modules.<module>.enabled: true`. That broke
    on the very first install where any module-with-eagerly-imported-deps
    was disabled — `services/__init__.py` and `app.py` both load several
    service files at startup (velociraptor_service, kape_service,
    msi_generator_service, velociraptor_init_service, elasticsearch_service)
    that import their module packages at module top-of-file, not lazily
    inside functions. With those packages missing, Flask crashed at
    import time, the container crashlooped, /api/health never responded,
    and the installer reported "Installation Complete!" with exit 0
    (see install_20260607_080121.log).

Why this is the right shape:
    Module-specific dep grouping (`requirements-velociraptor.txt` etc.)
    still has documentation value — anyone reading them knows "these are
    the packages the velociraptor module needs". The bug was in the
    conditional installation, not in the grouping. Always-install
    matches the actual import behaviour in the Python code.

    Service files for modules that DO use lazy imports (e.g. timesketch
    only does `from timesketch_api_client import client as ts_client`
    inside functions) are unaffected — their packages would still
    install but only get loaded if the operator triggers those code paths.

Disk cost: ~50-80 MB for the union of all per-module packages on top of
core. Worth it to never crashloop on a disabled-module install again.
"""
import os
import subprocess
import sys

req_dir = sys.argv[2] if len(sys.argv) > 2 else '/app'

# Module list intentionally listed for self-documentation. Anything new
# under requirements-<mod>.txt gets picked up automatically by the glob
# below — the list is just an ordering hint so installs happen in a
# predictable order in the logs.
MODULES = ['velociraptor', 'timesketch', 'elk', 'agentic', 'o365rc']

for mod in MODULES:
    req = os.path.join(req_dir, f'requirements-{mod}.txt')
    if not os.path.exists(req):
        continue
    print(f'[INSTALL] Installing {mod} dependencies (unconditional)...')
    subprocess.check_call(
        [sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '-r', req]
    )

# Catch any future requirements-<x>.txt that aren't in MODULES above.
for fn in sorted(os.listdir(req_dir)):
    if not fn.startswith('requirements-') or not fn.endswith('.txt'):
        continue
    mod = fn[len('requirements-'):-len('.txt')]
    if mod in MODULES:
        continue
    req = os.path.join(req_dir, fn)
    print(f'[INSTALL] Installing {mod} dependencies (unconditional, auto-discovered)...')
    subprocess.check_call(
        [sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '-r', req]
    )
