#!/bin/bash
# Alternative MSI repacking script using VQL query
# This script calls the Server.Utils.CreateMSI artifact via VQL

set -e

echo "========================================="
echo "MSI Repacking Fix Script"
echo "Using Server.Utils.CreateMSI artifact"
echo "========================================="

VELOCIRAPTOR="/velociraptor/velociraptor"
CONFIG="/velociraptor/server.config.yaml"
OUTPUT_DIR="/velociraptor/clients/windows"

# Wait for server to be ready
echo "Waiting for server to initialize..."
sleep 5

# Create VQL query to run Server.Utils.CreateMSI
cat > /tmp/create_msi.vql <<'EOF'
LET MSI_Collection = SELECT * FROM Artifact.Server.Utils.CreateMSI(
    AlsoBuild_x86=FALSE
)

SELECT * FROM MSI_Collection
EOF

echo "Running Server.Utils.CreateMSI artifact..."
$VELOCIRAPTOR --config $CONFIG query /tmp/create_msi.vql 2>&1 | grep -E "Path|Success|Error" || true

echo "MSI creation complete!"
echo "Check the server artifacts page for the repacked MSI files"
