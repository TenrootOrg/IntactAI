#!/bin/bash
set -e

# Configuration
BIND_ADDRESS=${BIND_ADDRESS:-"0.0.0.0"}
PUBLIC_PATH=${PUBLIC_PATH:-"public"}
CLIENT_DIR=${CLIENT_DIR:-"/velociraptor/clients"}

# Copy binaries
cp /opt/velociraptor/linux/velociraptor . && chmod +x velociraptor
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
        "API": {"bind_address": "0.0.0.0"},
        "GUI": {
            "bind_address": "0.0.0.0",
            "base_path": "/velociraptor",
            "public_url": "http://'$VELOX_FRONTEND_HOSTNAME'/velociraptor/app/index.html",
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

# Always check and create admin user if not exists
if [[ -n "$VELOX_USER" && -n "$VELOX_PASSWORD" && -n "$VELOX_ROLE" ]]; then
    USER_EXISTS=$(./velociraptor --config server.config.yaml user show "$VELOX_USER" 2>/dev/null || true)
    if [[ -z "$USER_EXISTS" ]]; then
        echo "Creating admin user: $VELOX_USER"
        ./velociraptor --config server.config.yaml user add "$VELOX_USER" "$VELOX_PASSWORD" --role "$VELOX_ROLE"
    fi
fi

# Create API user if specified
if [[ -n "$VELOX_USER_2" && -n "$VELOX_PASSWORD_2" && -n "$VELOX_ROLE_2" ]]; then
    USER_EXISTS=$(./velociraptor --config server.config.yaml user show "$VELOX_USER_2" 2>/dev/null || true)
    if [[ -z "$USER_EXISTS" ]]; then
        echo "Creating API user: $VELOX_USER_2"
        ./velociraptor --config server.config.yaml user add "$VELOX_USER_2" "$VELOX_PASSWORD_2" --role "$VELOX_ROLE_2"
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
        echo "1. Access Velociraptor GUI at: http://$VELOX_FRONTEND_HOSTNAME/velociraptor/"
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
