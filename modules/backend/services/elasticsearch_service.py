#!/usr/bin/env python3
"""
Elasticsearch Service - Persistent storage for workflow runs
"""

from elasticsearch import Elasticsearch
from datetime import datetime
import traceback

# Elasticsearch client instance
es_client = None

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

def update_workflow_status(run_id, status, progress=None, error=None):
    """Update workflow run status using partial update"""
    if not es_client:
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
        print(f"[ELASTICSEARCH] ✗ Failed to update status: {e}", flush=True)
        return False

def get_all_workflow_runs(size=100):
    """Get all workflow runs, sorted by started_at descending"""
    if not es_client:
        print("[ELASTICSEARCH] ✗ Client not initialized", flush=True)
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
        print(f"[ELASTICSEARCH] ✗ Failed to get workflow runs: {e}", flush=True)
        return []

def get_workflow_run(run_id):
    """Get a specific workflow run by ID"""
    if not es_client:
        return None

    try:
        result = es_client.get(index='intact_workflow_runs', id=run_id)
        return result['_source']

    except Exception as e:
        print(f"[ELASTICSEARCH] ✗ Failed to get workflow run: {e}", flush=True)
        return None
