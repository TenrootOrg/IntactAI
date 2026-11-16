#!/bin/bash
set -e

# Configuration
BIND_ADDRESS=${BIND_ADDRESS:-"0.0.0.0"}
PUBLIC_PATH=${PUBLIC_PATH:-"public"}
CLIENT_DIR=${CLIENT_DIR:-"/velociraptor/clients"}

# Copy binaries.
#
# `chmod 755`, not `chmod +x`. A symbolic mode with no "who" is masked by the
# umask -- so under a umask that includes execute bits, `+x` silently leaves
# the binary non-executable. That is what happened here: the server itself runs
# from the image copy and came up fine, so nothing looked wrong, while
# /velociraptor/velociraptor on the bind mount sat at 0644.
#
# Everything that shells out to `docker exec intact_velociraptor
# /velociraptor/velociraptor ... query` then fails with rc=126 (found, not
# executable). That is the memory-acquisition pipeline and the flow-cancel
# cleanup path, and the failure surfaces as an opaque "VQL query failed
# (rc=126)" rather than a permissions error. An explicit numeric mode cannot be
# masked.
cp /opt/velociraptor/linux/velociraptor . && chmod 755 velociraptor
mkdir -p $CLIENT_DIR/linux && cp /opt/velociraptor/linux/velociraptor $CLIENT_DIR/linux/velociraptor_client
mkdir -p $CLIENT_DIR/mac && cp /opt/velociraptor/mac/velociraptor_client $CLIENT_DIR/mac/velociraptor_client
mkdir -p $CLIENT_DIR/windows && cp /opt/velociraptor/windows/velociraptor_client* $CLIENT_DIR/windows/

# Generate server config if not exists
if [ ! -f server.config.yaml ]; then
    echo "Generating server configuration..."
    ./velociraptor config generate --merge '{
        "Frontend": {
            "public_path": "'$PUBLIC_PATH'",
            "hostname": "'$VELOX_FRONTEND_HOSTNAME'",
            "bind_address": "0.0.0.0"
        },
        "API": {"bind_address": "0.0.0.0", "hostname": "127.0.0.1"},
        "GUI": {
            "bind_address": "0.0.0.0",
            "base_path": "/velociraptor",
            "public_url": "https://'$VELOX_FRONTEND_HOSTNAME'/velociraptor/app/index.html",
            "use_plain_http": true
        },
        "Monitoring": {"bind_address": "0.0.0.0"},
        "Client": {
            "server_urls": ["'$VELOX_SERVER_URL'"],
            "use_self_signed_ssl": true
        }
    }' > server.config.yaml

    sed -i 's#/tmp/velociraptor#.#g' server.config.yaml
fi

# Self-heal API.hostname on a config generated before it was set (the block
# above only runs when server.config.yaml is absent, so every existing install
# needs this).
#
# The GUI talks to its own API over gRPC, and builds that address from
# API.hostname — falling back to Frontend.hostname when unset. Frontend.hostname
# is the box's PUBLIC address, and ports 8001/8889 are deliberately published on
# 127.0.0.1 only (see docker-compose.yaml: the GUI runs plain HTTP and the API
# can task endpoints, so neither belongs on a public interface). So the GUI left
# the container, dialled <public-ip>:8001, and got connection refused — the whole
# UI then failed with:
#
#   connection error: desc = "transport: Error while dialing:
#   dial tcp <public-ip>:8001: connect: connection refused"
#
# and every /velociraptor/api/v1/* call returned 503, while the API itself was
# perfectly healthy and listening on 0.0.0.0:8001 inside the container.
#
# Pinning it to 127.0.0.1 keeps the GUI's gRPC connection inside the container.
# This changes only the address the GUI DIALS — bind_address stays 0.0.0.0, so
# the backend keeps reaching the API over the docker network via
# api.config.yaml's `api_connection_string: intact_velociraptor:8001`.
if [ -f server.config.yaml ] && ! grep -qE '^\s+hostname:\s*127\.0\.0\.1' server.config.yaml; then
    if grep -q '^API:' server.config.yaml; then
        echo "Pinning API.hostname to 127.0.0.1 (GUI -> API gRPC stays in-container)"
        # Insert inside the API: block only — anchored between `API:` and the
        # next top-level key so Frontend/GUI/Monitoring hostnames are untouched.
        sed -i '/^API:/,/^[A-Za-z]/ { /^  bind_port:/a\  hostname: 127.0.0.1
        }' server.config.yaml
    fi
fi

# Users. The passwords come from modules/velociraptor/secrets/creds.env
# (env_file in docker-compose.yaml), never printed here.
#
# WHY THEY ARE ON A COMMAND LINE: `velociraptor user add <user> [<password>]`
# has no stdin or file option -- without the argument it reads a TERMINAL and
# fails in a container ("inappropriate ioctl for device"), and the VQL
# user_create() does nothing offline (both checked on 0.77.3). The value is in
# this short-lived process's argv inside the container for well under a second.

# GUI user: the store is authoritative, the same way as `api` below. Its
# password is (re)applied whenever the stored VELOX_PASSWORD differs from the
# sha256 stamp of the last one applied, and the user is created when missing.
# That is what makes a revert by scripts/apply-passwords.sh safe: it puts the
# old value back in the store and drops the stamps, and the next start puts it
# back in the datastore -- even when the container was down for the revert and
# the old value could not be applied from outside (round 2 review).
#
# Deliberate: Intact owns these passwords. A password changed by hand in the
# Velociraptor UI is overwritten by the stored one at the next start after the
# store changes (or the stamp is dropped, or on the first start of this
# entrypoint on an old box, which has no stamp yet). Change it with
# sudo scripts/apply-passwords.sh instead.
GUI_PW_STAMP=.gui_pw.sha256
if [[ -n "$VELOX_USER" && -n "$VELOX_PASSWORD" && -n "$VELOX_ROLE" ]]; then
    # printf is a builtin: the value never reaches an argv here.
    GUI_PW_SUM=$(printf '%s' "$VELOX_PASSWORD" | sha256sum | cut -d' ' -f1)
    USER_EXISTS=$(./velociraptor --config server.config.yaml user show "$VELOX_USER" 2>/dev/null || true)
    if [[ -n "$USER_EXISTS" && "$(cat "$GUI_PW_STAMP" 2>/dev/null)" == "$GUI_PW_SUM" ]]; then
        echo "GUI user password unchanged: $VELOX_USER"
    else
        echo "Setting the password of the GUI user: $VELOX_USER"
        if ./velociraptor --config server.config.yaml user add "$VELOX_USER" "$VELOX_PASSWORD" --role "$VELOX_ROLE"; then
            (umask 077; printf '%s\n' "$GUI_PW_SUM" > "$GUI_PW_STAMP") && chmod 600 "$GUI_PW_STAMP" \
                || echo "WARNING: could not record the GUI user password stamp"
        else
            echo "WARNING: could not set the password of $VELOX_USER (left as it was)"
        fi
    fi
fi

# `api` IS the backend's API-certificate identity (`config api_client --name api`
# below) -- NEVER delete it. Its password is random (VELOX_PASSWORD_2), known to
# no human, and applied whenever it CHANGES: `user add` on an existing user only
# replaces the password, so this is what retires the public GUI login `api`
# carried on older boxes the moment the store holds a random value. Failure is
# a warning, not an exit (set -e): it must not keep the server from starting.
#
# Only on change (red team): re-applying on every start put the value in argv
# on every boot. The sha256 of the last applied value sits in a root-only file
# in this persistent dir (the bind mount), written only after `user add`
# succeeded, so a failed apply is retried on the next start.
VELOX_USER_2="${VELOX_USER_2:-api}"
VELOX_ROLE_2="${VELOX_ROLE_2:-api,administrator}"
API_PW_STAMP=.api_pw.sha256
if [[ -n "$VELOX_PASSWORD_2" ]]; then
    # printf is a builtin: the value never reaches an argv here.
    API_PW_SUM=$(printf '%s' "$VELOX_PASSWORD_2" | sha256sum | cut -d' ' -f1)
    if [[ "$(cat "$API_PW_STAMP" 2>/dev/null)" == "$API_PW_SUM" ]]; then
        echo "API user password unchanged: $VELOX_USER_2"
    else
        echo "Setting the password of the API user: $VELOX_USER_2"
        if ./velociraptor --config server.config.yaml user add "$VELOX_USER_2" "$VELOX_PASSWORD_2" --role "$VELOX_ROLE_2"; then
            (umask 077; printf '%s\n' "$API_PW_SUM" > "$API_PW_STAMP") && chmod 600 "$API_PW_STAMP" \
                || echo "WARNING: could not record the API user password stamp"
        else
            echo "WARNING: could not set the password of $VELOX_USER_2 (left as it was)"
        fi
    fi
fi

# Skip certificate rotation for now - certificates are generated fresh on first run
# and typically valid for 10 years
echo "Skipping certificate check (using generated certificates)"

# Generate client config
echo "Generating client config..."
./velociraptor --config server.config.yaml config client > client.config.yaml || true

# Generate API config for backend integration
echo "Generating API config for backend..."
./velociraptor --config server.config.yaml config api_client \
    --name api \
    --role administrator,api \
    api.config.yaml 2>/dev/null || true

# Update API connection string to use container name for docker networking
if [ -f api.config.yaml ] && [ -s api.config.yaml ]; then
    # Check if it's a valid config file (not an error message)
    if grep -q "api_connection_string" api.config.yaml 2>/dev/null; then
        sed -i 's/api_connection_string: .*/api_connection_string: intact_velociraptor:8001/' api.config.yaml
        echo "API config generated successfully at api.config.yaml"
    fi
fi

# Repack clients with server configuration
echo "Repacking client binaries with server configuration..."
echo "Using platform-specific binaries as source..."

# Linux client - use LINUX binary as source
if [ -f client.config.yaml ]; then
    echo "Repacking Linux client..."
    ./velociraptor config repack --exe /opt/velociraptor/linux/velociraptor client.config.yaml $CLIENT_DIR/linux/velociraptor_client 2>&1 | grep -v "WARNING" || true
fi

# Mac client - use MAC binary as source
if [ -f client.config.yaml ]; then
    echo "Repacking Mac client..."
    ./velociraptor config repack --exe /opt/velociraptor/mac/velociraptor_client client.config.yaml $CLIENT_DIR/mac/velociraptor_client 2>&1 | grep -v "WARNING" || true
fi

# Windows EXE client - use WINDOWS binary as source
if [ -f client.config.yaml ]; then
    echo "Repacking Windows EXE client..."
    ./velociraptor config repack --exe /opt/velociraptor/windows/velociraptor_client.exe client.config.yaml $CLIENT_DIR/windows/velociraptor_client.exe 2>&1 | grep -v "WARNING" || true
fi

# Windows MSI client - KNOWN ISSUE: CLI repack doesn't embed config properly
if [ -f client.config.yaml ] && [ -f /opt/velociraptor/windows/velociraptor_client.msi ]; then
    echo "Attempting Windows MSI repacking (may fail silently in v0.75.x)..."
    ./velociraptor config repack --msi /opt/velociraptor/windows/velociraptor_client.msi client.config.yaml $CLIENT_DIR/windows/velociraptor_client.msi 2>&1 | grep -v "WARNING" || true

    # VERIFY if config was actually embedded
    echo "Verifying MSI embedded config..."
    VERIFY_RESULT=$(./velociraptor --embedded_config $CLIENT_DIR/windows/velociraptor_client.msi config show 2>&1 | head -5)

    if echo "$VERIFY_RESULT" | grep -q "Unable to load config"; then
        echo ""
        echo "================================================================================================"
        echo "⚠️  WARNING: MSI repacking FAILED - Config was not embedded!"
        echo "================================================================================================"
        echo ""
        echo "This is a known issue in Velociraptor 0.75.x where CLI 'config repack' fails silently for MSI files."
        echo ""
        echo "SOLUTION: Use the Server.Utils.CreateMSI artifact instead:"
        echo ""
        echo "1. Access Velociraptor GUI at: https://$VELOX_FRONTEND_HOSTNAME/velociraptor/"
        echo "2. Go to: Server Artifacts (sidebar)"
        echo "3. Click: '+ New Collection'"
        echo "4. Search for: Server.Utils.CreateMSI"
        echo "5. Click: 'Launch'"
        echo "6. Wait for completion, then download from 'Uploaded Files' tab"
        echo ""
        echo "That MSI will have the correct embedded configuration."
        echo "================================================================================================"
        echo ""

        # Create README in the clients directory
        cat > $CLIENT_DIR/windows/README_MSI_BROKEN.txt <<'README_EOF'
⚠️  WARNING: The velociraptor_client.msi in this directory does NOT have embedded config!

This is a known issue in Velociraptor 0.75.x where command-line MSI repacking fails silently.

TO GET A PROPERLY CONFIGURED MSI:

1. Access Velociraptor Web GUI
2. Go to "Server Artifacts" in the sidebar
3. Click "+ New Collection"
4. Search for "Server.Utils.CreateMSI"
5. Click "Launch"
6. Wait for it to complete
7. Download the MSI from "Uploaded Files" tab

That MSI will have the correct embedded server configuration and will work properly.

Alternatively, use the Windows EXE client:
  velociraptor_client.exe service install

The EXE client has the config embedded correctly and works fine.
README_EOF
    else
        echo "✓ MSI embedded config verification: OK"
    fi
else
    echo "Warning: Windows MSI source file not found, skipping MSI repacking"
fi

echo "Client repacking completed"
find "$CLIENT_DIR" -type f -exec chmod 755 {} \;

# Start Velociraptor.
#
# --definitions /opt/velociraptor_artifacts loads the curated artifact
# bundle (ArtifactExchange / DetectRaptor / Sigma / Rapid7 / TenRoot —
# baked into the image, see Dockerfile) directly from disk at startup. This
# replaces the old per-artifact API import (artifact_set over gRPC, one
# round-trip + full repository recompile each, ~O(N^2)) which took ~37 min
# on a fresh air-gap install with a large artifact set. The directory load
# is a single pass (~0.5s for 400 artifacts). Definitions loaded this way
# are read-only/built-in and refresh automatically when the image is
# rebuilt with an updated bundle.
echo "Starting Velociraptor frontend..."
exec ./velociraptor --config server.config.yaml --definitions /opt/velociraptor_artifacts frontend -v
