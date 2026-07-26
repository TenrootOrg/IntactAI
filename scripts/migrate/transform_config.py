#!/usr/bin/env python3
"""Transform a legacy risx-mssp Velociraptor server.config.yaml into the
shape intact's velociraptor container expects, preserving the deployment
identity (CA, frontend certs, nonce, server_urls) so every already-deployed
client keeps connecting with its existing client_id.

Identity — copied through untouched:
    CA.private_key, Client.ca_certificate, Client.nonce, Client.server_urls,
    Frontend.certificate/private_key, GUI.gw_certificate/gw_private_key,
    obfuscation_nonce (datastore filenames are obfuscated with it — a new
    nonce would make the transplanted datastore unreadable).

Rewritten to intact's layout:
    Datastore/filestore -> /var./ (intact mounts the datastore volume there;
    legacy used relative "./" inside one big bind dir), Logging block,
    GUI.public_url, and any leftover relative paths.

Removed:
    Frontend.default_server_monitoring_artifacts (legacy ships
    Custom.Elastic.Flows.Upload which streams to the retired risx ELK).

Usage:
    transform_config.py IN.yaml OUT.yaml --domain 192.168.120.11
"""

import argparse
import hashlib
import sys

try:
    import yaml
except ImportError:
    sys.stderr.write("PyYAML is required (apt install python3-yaml)\n")
    sys.exit(3)

DATASTORE = "/var./"

# What intact's entrypoint-generated config uses; keep the transplant
# byte-compatible with a native install for everything that is not identity.
INTACT_LOGGING = {
    "separate_logs_per_component": True,
    "debug": {"disabled": True},
    "info": {"rotation_time": 604800, "max_age": 31536000},
    "error": {"rotation_time": 604800, "max_age": 31536000},
}

REQUIRED_IDENTITY = (
    ("CA", "private_key"),
    ("Client", "ca_certificate"),
    ("Client", "nonce"),
    ("Client", "server_urls"),
    ("Frontend", "certificate"),
    ("Frontend", "private_key"),
)

# The compose port map and nginx location are fixed; a legacy box that
# deviates from these needs manual attention, not a silent rewrite.
SHAPE_ASSERTS = (
    ("API", "bind_port", 8001),
    ("Frontend", "bind_port", 8000),
    ("GUI", "bind_port", 8889),
)


def fp(pem: str) -> str:
    return hashlib.sha256((pem or "").encode()).hexdigest()[:16]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("infile")
    ap.add_argument("outfile")
    ap.add_argument("--domain", required=True,
                    help="intact's config.yaml domain (must be the host the "
                         "deployed clients dial in server_urls)")
    ap.add_argument("--allow-shape-mismatch", action="store_true",
                    help="continue even if ports/base_path deviate from the "
                         "intact layout (you must fix compose/nginx yourself)")
    args = ap.parse_args()

    with open(args.infile) as f:
        cfg = yaml.safe_load(f)
    if not isinstance(cfg, dict):
        sys.stderr.write("ERROR: input is not a YAML mapping\n")
        return 2

    problems = []
    for sect, key in REQUIRED_IDENTITY:
        if not (cfg.get(sect) or {}).get(key):
            problems.append(f"missing identity field {sect}.{key}")
    if problems:
        for p in problems:
            sys.stderr.write(f"ERROR: {p}\n")
        sys.stderr.write("Refusing: this file cannot preserve the client "
                         "trust chain.\n")
        return 2

    for sect, key, want in SHAPE_ASSERTS:
        got = (cfg.get(sect) or {}).get(key)
        if got != want:
            msg = f"{sect}.{key} is {got!r}, intact expects {want!r}"
            if args.allow_shape_mismatch:
                sys.stderr.write(f"WARN: {msg}\n")
            else:
                sys.stderr.write(f"ERROR: {msg} (compose publishes fixed "
                                 f"ports; use --allow-shape-mismatch to "
                                 f"override)\n")
                return 2

    changed = []

    ds = cfg.setdefault("Datastore", {})
    for key in ("location", "filestore_directory"):
        if ds.get(key) != DATASTORE:
            changed.append(f"Datastore.{key}: {ds.get(key)!r} -> {DATASTORE!r}")
            ds[key] = DATASTORE
    ds.setdefault("implementation", "FileBaseDataStore")

    if cfg.get("Logging") != INTACT_LOGGING:
        changed.append("Logging: replaced with intact block")
        cfg["Logging"] = INTACT_LOGGING

    fe = cfg["Frontend"]
    if "default_server_monitoring_artifacts" in fe:
        changed.append("Frontend.default_server_monitoring_artifacts: "
                       f"removed {fe['default_server_monitoring_artifacts']!r}")
        del fe["default_server_monitoring_artifacts"]
    # Velociraptor >=0.76 removed Frontend.public_path from the schema and
    # the strict config parser hard-fails on unknown fields (E2E: 0.77.1
    # crash-looped on a 0.75 config that kept it). Drop legacy-only fields.
    if "public_path" in fe:
        changed.append(f"Frontend.public_path: removed {fe['public_path']!r} "
                       f"(field no longer exists in 0.76+)")
        del fe["public_path"]

    gui = cfg.setdefault("GUI", {})
    # legacy wired a reverse proxy to its Kibana, which no longer exists
    if "reverse_proxy" in gui:
        changed.append(f"GUI.reverse_proxy: removed {gui['reverse_proxy']!r}")
        del gui["reverse_proxy"]
    new_url = f"http://{args.domain}/velociraptor/app/index.html"
    if gui.get("public_url") != new_url:
        changed.append(f"GUI.public_url: {gui.get('public_url')!r} -> {new_url!r}")
        gui["public_url"] = new_url
    for key, want in (("base_path", "/velociraptor"),
                      ("use_plain_http", True),
                      ("bind_address", "0.0.0.0")):
        if gui.get(key) != want:
            changed.append(f"GUI.{key}: {gui.get(key)!r} -> {want!r}")
            gui[key] = want
    for sect in ("API", "Frontend"):
        if cfg[sect].get("bind_address") != "0.0.0.0":
            changed.append(f"{sect}.bind_address: "
                           f"{cfg[sect].get('bind_address')!r} -> '0.0.0.0'")
            cfg[sect]["bind_address"] = "0.0.0.0"

    # Any other relative path left over from the legacy "everything under
    # one bind dir" layout would resolve against the container CWD; rebase.
    def rebase(node, path=""):
        if isinstance(node, dict):
            for k, v in node.items():
                where = f"{path}.{k}" if path else k
                if isinstance(v, str) and (v == "." or v.startswith("./")) \
                        and ("location" in k or k.endswith(("_directory", "_path", "_dir"))):
                    nv = DATASTORE + v.lstrip("./")
                    changed.append(f"{where}: {v!r} -> {nv!r}")
                    node[k] = nv
                else:
                    rebase(v, where)

    rebase(cfg)

    with open(args.outfile, "w") as f:
        yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False,
                       width=4096)

    urls = ", ".join(cfg["Client"]["server_urls"])
    print(f"identity preserved: CA fp={fp(cfg['CA']['private_key'])} "
          f"nonce={cfg['Client']['nonce']} server_urls=[{urls}]")
    host = urls.split("://", 1)[-1].split(":", 1)[0].split("/", 1)[0]
    if host != args.domain:
        print(f"WARNING: server_urls host {host!r} != --domain "
              f"{args.domain!r} — deployed clients dial {host!r}; intact's "
              f"domain MUST match or every client is stranded.")
    for c in changed:
        print(f"  ~ {c}")
    if not changed:
        print("  (no structural changes were needed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
