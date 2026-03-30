"""Install module dependencies based on config.yaml."""
import yaml, subprocess, sys, os

config_file = sys.argv[1] if len(sys.argv) > 1 else '/app/config.yaml'
req_dir = sys.argv[2] if len(sys.argv) > 2 else '/app'

try:
    with open(config_file) as f:
        config = yaml.safe_load(f)
    modules = config.get('modules', {})
except Exception:
    modules = {}

for mod in ['velociraptor', 'timesketch', 'elk', 'agentic', 'azure']:
    req = os.path.join(req_dir, f'requirements-{mod}.txt')
    if not os.path.exists(req):
        continue
    mc = modules.get(mod, {})
    enabled = mc.get('enabled', True) if isinstance(mc, dict) else True
    if enabled:
        print(f'[INSTALL] Installing {mod} dependencies...')
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--no-cache-dir', '-r', req])
    else:
        print(f'[INSTALL] Skipping {mod} (disabled in config.yaml)')
