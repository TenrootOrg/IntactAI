#!/usr/bin/env python3
"""
Create properly configured Windows MSI/EXE clients using Velociraptor API
This bypasses the broken CLI 'config repack' command and uses the working Server.Utils.CreateMSI artifact
"""

import grpc
import yaml
import json
import time
import sys
import os

# Import Velociraptor API
sys.path.append('/opt')
try:
    import pyvelociraptor
    from pyvelociraptor import api_pb2
    from pyvelociraptor import api_pb2_grpc
except ImportError:
    print("Installing pyvelociraptor...")
    os.system("pip3 install -q pyvelociraptor")
    import pyvelociraptor
    from pyvelociraptor import api_pb2
    from pyvelociraptor import api_pb2_grpc

def load_api_config(config_path="/velociraptor/api.config.yaml"):
    """Load API configuration"""
    with open(config_path, 'r') as f:
        return yaml.safe_load(f)

def create_msi_via_artifact(config):
    """Trigger Server.Utils.CreateMSI artifact to create properly configured MSI"""

    # Set up gRPC connection
    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode("utf8"),
        private_key=config["client_private_key"].encode("utf8"),
        certificate_chain=config["client_cert"].encode("utf8")
    )

    # Parse API connection string (format: hostname:port)
    api_connection = config.get("api_connection_string", "localhost:8001")

    print(f"Connecting to Velociraptor API at {api_connection}...")

    with grpc.secure_channel(api_connection, creds) as channel:
        stub = api_pb2_grpc.APIStub(channel)

        # Create artifact collection request
        request = api_pb2.ArtifactCollectorArgs(
            client_id="server",
            artifacts=["Server.Utils.CreateMSI"],
            urgent=True,
        )

        # Add parameter for AlsoBuild_x86
        param = request.specs[0].parameters.env.add()
        param.key = "AlsoBuild_x86"
        param.value = "N"  # Don't build 32-bit version

        print("Triggering Server.Utils.CreateMSI artifact...")
        try:
            response = stub.CollectArtifact(request)
            flow_id = response.flow_id
            print(f"✓ Artifact collection started: Flow ID {flow_id}")
            print(f"  The properly configured Windows MSI will be available in:")
            print(f"  Server Artifacts > Server.Utils.CreateMSI > Uploads tab")
            return True
        except Exception as e:
            print(f"✗ Error triggering artifact: {e}")
            return False

def main():
    """Main execution"""
    api_config_path = "/velociraptor/api.config.yaml"

    # Wait for API config to be ready
    for i in range(30):
        if os.path.exists(api_config_path):
            break
        print(f"Waiting for API config... ({i+1}/30)")
        time.sleep(2)

    if not os.path.exists(api_config_path):
        print("✗ API config not found. Cannot create MSI clients.")
        return False

    # Wait a bit more for server to be fully ready
    print("Waiting for server to be fully initialized...")
    time.sleep(10)

    try:
        config = load_api_config(api_config_path)
        success = create_msi_via_artifact(config)

        if success:
            print("\n" + "="*60)
            print("Windows client MSI creation initiated successfully!")
            print("="*60)
            print("\nTo download the properly configured MSI:")
            print("1. Go to Velociraptor GUI")
            print("2. Click 'Server Artifacts' in the sidebar")
            print("3. Find 'Server.Utils.CreateMSI' collection")
            print("4. Click 'Uploaded Files' tab")
            print("5. Download the MSI file")
            print("\nThe MSI will have the correct embedded configuration.")
            print("="*60)

        return success
    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    sys.exit(0 if main() else 1)
