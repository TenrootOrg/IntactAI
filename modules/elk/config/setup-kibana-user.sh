#!/bin/bash
# One-shot init container script: sets the password of the built-in,
# reserved `kibana_system` service account via the Elasticsearch Security
# API, authenticating as the `elastic` superuser.
#
# Why this exists: Kibana must NOT authenticate to Elasticsearch as the
# `elastic` superuser — Elasticsearch/Kibana 9.x reject that outright
# ("value of 'elastic' is forbidden ... Use a service account token
# instead"). The dedicated `kibana_system` account is meant for exactly
# this, but it ships with no usable password until one is set here.
#
# Idempotent: re-running this (e.g. on every `docker compose up`) simply
# resets kibana_system's password to the same configured value again.
set -euo pipefail

ES_URL="http://elasticsearch:9200"

: "${ELASTIC_PASSWORD:?ELASTIC_PASSWORD must be set}"
: "${KIBANA_PASSWORD:?KIBANA_PASSWORD must be set}"

echo "[elk-setup] Waiting for Elasticsearch to accept 'elastic' credentials..."
until curl -sf -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" >/dev/null 2>&1; do
  sleep 3
done

echo "[elk-setup] Setting kibana_system password..."
http_code=$(curl -s -o /tmp/kibana-user-setup-response.json -w '%{http_code}' \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -X POST "${ES_URL}/_security/user/kibana_system/_password" \
  -H 'Content-Type: application/json' \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}")

if [[ "$http_code" == "200" ]]; then
  echo "[elk-setup] kibana_system password set successfully."
  exit 0
fi

echo "[elk-setup] Failed to set kibana_system password (HTTP ${http_code}):"
cat /tmp/kibana-user-setup-response.json 2>/dev/null || true
exit 1
