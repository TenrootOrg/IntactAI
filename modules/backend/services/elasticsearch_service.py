#!/usr/bin/env python3
"""
Elasticsearch Service - Persistent storage for workflow runs
"""

from elasticsearch import Elasticsearch
from datetime import datetime
import time
import traceback

try:
    from elasticsearch import ConnectionError as _ESConnectionError, ConnectionTimeout as _ESConnectionTimeout
    _UNREACHABLE = (_ESConnectionError, _ESConnectionTimeout)
except ImportError:  # an older client without the transport exceptions
    _UNREACHABLE = ()

# Elasticsearch client instance
es_client = None

# When Elasticsearch cannot be reached -- ELK stopped while config.yaml still says
# enabled, or not up yet -- every call paid a name lookup plus the client's retries
# (2.2 s measured with a fresh client, ~0.5 s warm) before falling back to SQLite.
# Listing runs does that twice per request, and the Case Management page lists
# cases several times on load, so the page took seconds. After a CONNECTION failure
# every call returns its empty result at once for a short cool-down, then tries
# again, so ELK coming back is noticed within a minute. Any other error -- a missing
# document, a bad query -- still logs and returns exactly as before and never trips
# this, so a real problem is not hidden behind it. SQLite stays the store of record
# either way; nothing is written or skipped that would otherwise have succeeded.
_UNREACHABLE_COOLDOWN_S = 60
_unreachable_until = [0.0]


def _skip_while_unreachable() -> bool:
    return time.monotonic() < _unreachable_until[0]


def _note_failure(e, what) -> None:
    if _UNREACHABLE and isinstance(e, _UNREACHABLE):
        first = not _skip_while_unreachable()
        _unreachable_until[0] = time.monotonic() + _UNREACHABLE_COOLDOWN_S
        if first:
            print(f"[ELASTICSEARCH] ✗ unreachable while trying to {what}; skipping it for "
                  f"{_UNREACHABLE_COOLDOWN_S}s: {e}", flush=True)
        return
    print(f"[ELASTICSEARCH] ✗ Failed to {what}: {e}", flush=True)

def init_elasticsearch(host='elasticsearch', port=9200, user=None, password=None):
    """Initialize Elasticsearch connection"""
    global es_client

    try:
        client_kwargs = {
            'request_timeout': 10,
            'retry_on_timeout': True,
            'max_retries': 3
        }
        if user and password:
            client_kwargs['basic_auth'] = (user, password)

        es_client = Elasticsearch(
            [f'http://{host}:{port}'],
            **client_kwargs
        )

        # Test connection
        if es_client.ping():
            print(f"[ELASTICSEARCH] ✓ Connected to Elasticsearch at {host}:{port}", flush=True)

            # Create index if it doesn't exist
            index_name = 'intact_workflow_runs'
            if not es_client.indices.exists(index=index_name):
                # Define index mapping
                mapping = {
                    "mappings": {
                        "properties": {
                            "id": {"type": "keyword"},
                            "type": {"type": "keyword"},
                            "name": {"type": "text"},
                            "details": {"type": "object", "enabled": True},
                            "status": {"type": "keyword"},
                            "started_at": {"type": "date"},
                            "completed_at": {"type": "date"},
                            "logs": {
                                "type": "nested",
                                "properties": {
                                    "timestamp": {"type": "date"},
                                    "level": {"type": "keyword"},
                                    "message": {"type": "text"}
                                }
                            },
                            "progress": {"type": "integer"},
                            "error": {"type": "text"}
                        }
                    }
                }
                es_client.indices.create(index=index_name, body=mapping)
                print(f"[ELASTICSEARCH] ✓ Created index: {index_name}", flush=True)
            else:
                print(f"[ELASTICSEARCH] ✓ Index already exists: {index_name}", flush=True)

            return True
        else:
            print("[ELASTICSEARCH] ✗ Failed to ping Elasticsearch", flush=True)
            return False

    except Exception as e:
        print(f"[ELASTICSEARCH] ✗ Connection failed: {e}", flush=True)
        traceback.print_exc()
        return False

def delete_workflow_run(run_id):
    """Remove a run's document. There was no delete here at all, so a run deleted
    from SQLite lived on in Elasticsearch — and get_all_automation_runs() MERGES
    ES rows whose run_id is not in SQLite, which is exactly what a delete creates.
    The deleted runs came back in the workflow list, with their logs, untagged."""
    if not es_client or _skip_while_unreachable():
        return False
    try:
        es_client.delete(index='intact_workflow_runs', id=run_id, ignore=[404])
        return True
    except Exception as e:
        _note_failure(e, "delete run")
        return False


def update_workflow_status(run_id, status, progress=None, error=None):
    """Update workflow run status using partial update"""
    if not es_client or _skip_while_unreachable():
        return False

    try:
        # Build update doc with only changed fields
        update_doc = {"status": status}
        if progress is not None:
            update_doc["progress"] = progress
        if error:
            update_doc["error"] = error
        if status in ["completed", "failed"]:
            update_doc["completed_at"] = datetime.now().isoformat()

        # Use partial update for efficiency
        es_client.update(
            index='intact_workflow_runs',
            id=run_id,
            body={"doc": update_doc},
            retry_on_conflict=3
        )

        return True

    except Exception as e:
        _note_failure(e, "update status")
        return False

def get_all_workflow_runs(size=100):
    """Get all workflow runs, sorted by started_at descending"""
    if not es_client:
        print("[ELASTICSEARCH] ✗ Client not initialized", flush=True)
        return []
    if _skip_while_unreachable():
        return []

    try:
        result = es_client.search(
            index='intact_workflow_runs',
            body={
                "query": {"match_all": {}},
                "sort": [{"started_at": {"order": "desc"}}],
                "size": size
            }
        )

        workflows = [hit['_source'] for hit in result['hits']['hits']]
        return workflows

    except Exception as e:
        _note_failure(e, "get workflow runs")
        return []

def get_workflow_run(run_id):
    """Get a specific workflow run by ID"""
    if not es_client or _skip_while_unreachable():
        return None

    try:
        result = es_client.get(index='intact_workflow_runs', id=run_id)
        return result['_source']

    except Exception as e:
        _note_failure(e, "get workflow run")
        return None
