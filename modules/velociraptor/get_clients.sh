#!/bin/bash
# Query Velociraptor clients using CLI and output JSON

cd /velociraptor

# Use velociraptor CLI to query clients
./velociraptor --config server.config.yaml query "SELECT client_id, os_info.hostname AS hostname, os_info.system AS os, last_seen_at FROM clients()" --format json 2>/dev/null
