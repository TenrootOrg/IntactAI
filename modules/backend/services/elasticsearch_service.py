#!/usr/bin/env python3
"""
Elasticsearch Service - Persistent storage for workflow runs
"""

from elasticsearch import Elasticsearch
from datetime import datetime
import traceback

# Elasticsearch client instance
es_client = None

def init_elasticsearch(host='elasticsearch', port=9200):
    """Initialize Elasticsearch connection"""
    global es_client

    try:
        es_client = Elasticsearch(
            [f'http://{host}:{port}'],
            request_timeout=10,
            retry_on_timeout=True,
            max_retries=3
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

def create_workflow_run(run_id, automation_type, name, details=None):
    """Create a new workflow run in Elasticsearch"""
    if not es_client:
        print("[ELASTICSEARCH] ✗ Client not initialized", flush=True)
        return False

    try:
        document = {
            "id": run_id,
            "type": automation_type,
            "name": name,
            "details": details or {},
            "status": "running",
            "started_at": datetime.now().isoformat(),
            "logs": [],
            "progress": 100  # Start at 100%, only set to 0 on failure
        }

        es_client.index(
            index='intact_workflow_runs',
            id=run_id,
            document=document
        )

        print(f"[ELASTICSEARCH] ✓ Created workflow run: {run_id}", flush=True)
        return True

    except Exception as e:
        print(f"[ELASTICSEARCH] ✗ Failed to create workflow run: {e}", flush=True)
        traceback.print_exc()
        return False

def add_log_to_workflow(run_id, log_message, log_level="info"):
    """Add a log entry to a workflow run using atomic update"""
    if not es_client:
        return False

    try:
        # Create log entry
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": log_level,
            "message": log_message
        }

        # Use update API with script to atomically append to logs array
        # This is more efficient and thread-safe than read-modify-write
        es_client.update(
            index='intact_workflow_runs',
            id=run_id,
            body={
                "script": {
                    "source": "ctx._source.logs.add(params.log)",
                    "lang": "painless",
                    "params": {
                        "log": log_entry
                    }
                }
            },
            retry_on_conflict=3  # Handle concurrent updates
        )

        return True

    except Exception as e:
        # If scripted update fails, fall back to full document update
        try:
            result = es_client.get(index='intact_workflow_runs', id=run_id)
            doc = result['_source']
            doc['logs'].append({
                "timestamp": datetime.now().isoformat(),
                "level": log_level,
                "message": log_message
            })
            es_client.index(
                index='intact_workflow_runs',
                id=run_id,
                document=doc
            )
            return True
        except Exception as e2:
            print(f"[ELASTICSEARCH] ✗ Failed to add log: {e2}", flush=True)
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

def search_workflow_runs(query, size=50):
    """Search workflow runs by name, type, or status"""
    if not es_client:
        return []

    try:
        result = es_client.search(
            index='intact_workflow_runs',
            body={
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": ["name", "type", "status", "details.*"]
                    }
                },
                "sort": [{"started_at": {"order": "desc"}}],
                "size": size
            }
        )

        workflows = [hit['_source'] for hit in result['hits']['hits']]
        return workflows

    except Exception as e:
        print(f"[ELASTICSEARCH] ✗ Failed to search workflow runs: {e}", flush=True)
        return []

def delete_old_workflow_runs(days=30):
    """Delete workflow runs older than specified days"""
    if not es_client:
        return 0

    try:
        # Calculate cutoff date
        from datetime import timedelta
        cutoff = datetime.now() - timedelta(days=days)

        result = es_client.delete_by_query(
            index='intact_workflow_runs',
            body={
                "query": {
                    "range": {
                        "started_at": {
                            "lt": cutoff.isoformat()
                        }
                    }
                }
            }
        )

        deleted = result.get('deleted', 0)
        print(f"[ELASTICSEARCH] ✓ Deleted {deleted} old workflow runs", flush=True)
        return deleted

    except Exception as e:
        print(f"[ELASTICSEARCH] ✗ Failed to delete old runs: {e}", flush=True)
        return 0

def get_workflow_stats():
    """Get statistics about workflow runs"""
    if not es_client:
        return {}

    try:
        result = es_client.search(
            index='intact_workflow_runs',
            body={
                "size": 0,
                "aggs": {
                    "by_status": {
                        "terms": {"field": "status"}
                    },
                    "by_type": {
                        "terms": {"field": "type"}
                    },
                    "total_runs": {
                        "value_count": {"field": "id"}
                    }
                }
            }
        )

        stats = {
            "total": result['hits']['total']['value'],
            "by_status": {bucket['key']: bucket['doc_count'] for bucket in result['aggregations']['by_status']['buckets']},
            "by_type": {bucket['key']: bucket['doc_count'] for bucket in result['aggregations']['by_type']['buckets']}
        }

        return stats

    except Exception as e:
        print(f"[ELASTICSEARCH] ✗ Failed to get stats: {e}", flush=True)
        return {}
