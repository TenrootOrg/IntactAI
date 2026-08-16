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

if [[ "$http_code" != "200" ]]; then
  echo "[elk-setup] Failed to set kibana_system password (HTTP ${http_code}):"
  cat /tmp/kibana-user-setup-response.json 2>/dev/null || true
  exit 1
fi
echo "[elk-setup] kibana_system password set successfully."

# ---------------------------------------------------------------------------
# Single-node clusters: replicas have nowhere to live.
#
# Elasticsearch defaults every index to one replica. On a one-node appliance
# that replica can never be allocated -- a replica on the same node as its
# primary would defeat the point -- so the shard sits unassigned forever and
# the cluster reports YELLOW. Permanently. It is not a transient startup state
# and no amount of waiting clears it.
#
# The health gate then reports the module DEGRADED on every single upgrade,
# which is worse than cosmetic: an operator who is told "degraded, that's
# normal" three times learns to ignore the health gate, and the one time it
# means something they will ignore it too. A warning that is always on is a
# warning that has been switched off.
#
# So on a single-node cluster, ask for zero replicas and get an honest GREEN.
# Guarded on the actual node count: the moment this is a real multi-node
# deployment, replicas matter and nothing here touches them.
nodes=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" \
        | sed -n 's/.*"number_of_nodes":\([0-9]*\).*/\1/p')
if [[ "$nodes" == "1" ]]; then
  echo "[elk-setup] Single-node cluster — setting replicas to 0 (a replica cannot be allocated on one node, which is what leaves the cluster yellow forever)."

  # New indices, including the ones Kibana creates later.
  #
  # priority 0 ON PURPOSE — do not raise it. Composable templates do not merge;
  # the highest-priority match wins outright, so a `*` template above Elastic's
  # own logs-*-* / metrics-*-* templates would replace their ECS mappings along
  # with the replica count. This container is also a one-shot that completes
  # BEFORE Kibana starts, so it cannot see the indices Kibana creates minutes
  # later — which is why the cluster was observed drifting back to yellow after
  # this script correctly reported green (2026-08-16). The follow-up sweep lives
  # in elk_settle_single_node_replicas() (lib/modules/elk.sh), which runs late in
  # the install and only when the cluster is actually single-node and yellow.
  curl -s -o /dev/null -u "elastic:${ELASTIC_PASSWORD}" \
    -X PUT "${ES_URL}/_index_template/intact-single-node" \
    -H 'Content-Type: application/json' \
    -d '{"index_patterns":["*"],"priority":0,"template":{"settings":{"number_of_replicas":0}}}' \
    || echo "[elk-setup] (index template not applied — new indices may start yellow)"

  # Indices that already exist, system/hidden ones included: those are exactly
  # the .kibana* and .security* indices that keep the cluster yellow on their own.
  curl -s -o /dev/null -u "elastic:${ELASTIC_PASSWORD}" \
    -X PUT "${ES_URL}/*/_settings?expand_wildcards=all" \
    -H 'Content-Type: application/json' \
    -d '{"index":{"number_of_replicas":0}}' \
    || echo "[elk-setup] (existing indices not updated — cluster may stay yellow)"

  # Report what it actually achieved rather than assuming.
  for _ in $(seq 1 10); do
    st=$(curl -s -u "elastic:${ELASTIC_PASSWORD}" "${ES_URL}/_cluster/health" \
         | sed -n 's/.*"status":"\([a-z]*\)".*/\1/p')
    [[ "$st" == "green" ]] && break
    sleep 2
  done
  echo "[elk-setup] Cluster status now: ${st:-unknown}"
fi
exit 0

