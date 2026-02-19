#!/usr/bin/env python3
"""
VQL Utilities - Common Velociraptor query patterns

This module provides reusable helper functions for executing VQL queries
via gRPC. It extracts common patterns to reduce code duplication without
changing any existing logic.
"""

import json
from pyvelociraptor import api_pb2


def execute_vql(stub, query, timeout=30, max_wait=10, max_row=1000):
    """
    Execute a VQL query and return parsed JSON results.

    Args:
        stub: gRPC API stub from setup_velociraptor_connection()
        query: VQL query string
        timeout: gRPC timeout in seconds (default: 30)
        max_wait: Max wait time for results (default: 10)
        max_row: Max rows to return (default: 1000)

    Returns:
        list: Parsed JSON results (flat list of all rows)

    Example:
        channel = setup_velociraptor_connection()
        stub = api_pb2_grpc.APIStub(channel)
        results = execute_vql(stub, "SELECT * FROM clients()")
        channel.close()
    """
    request = api_pb2.VQLCollectorArgs(
        max_wait=max_wait,
        max_row=max_row,
        Query=[api_pb2.VQLRequest(VQL=query)]
    )

    results = []
    for response in stub.Query(request, timeout=timeout):
        if response.Response:
            try:
                data = json.loads(response.Response)
                if isinstance(data, list):
                    results.extend(data)
                elif isinstance(data, dict):
                    results.append(data)
            except json.JSONDecodeError:
                pass

    return results


def execute_vql_single(stub, query, timeout=30, max_wait=10):
    """
    Execute a VQL query and return the first result or None.

    Useful for queries that return a single row (e.g., flow status).

    Args:
        stub: gRPC API stub
        query: VQL query string
        timeout: gRPC timeout in seconds
        max_wait: Max wait time for results

    Returns:
        dict or None: First result row, or None if no results
    """
    results = execute_vql(stub, query, timeout=timeout, max_wait=max_wait, max_row=1)
    return results[0] if results else None


def execute_vql_raw(stub, query, timeout=30, max_wait=10, max_row=1000):
    """
    Execute a VQL query and return raw responses (for streaming/logs).

    This is useful when you need access to response.log or need to
    process responses as they arrive.

    Args:
        stub: gRPC API stub
        query: VQL query string
        timeout: gRPC timeout in seconds
        max_wait: Max wait time for results
        max_row: Max rows to return

    Yields:
        response: Raw gRPC response objects
    """
    request = api_pb2.VQLCollectorArgs(
        max_wait=max_wait,
        max_row=max_row,
        Query=[api_pb2.VQLRequest(VQL=query)]
    )

    for response in stub.Query(request, timeout=timeout):
        yield response


def safe_json_parse(json_string, default=None):
    """
    Safely parse JSON string, returning default on failure.

    Args:
        json_string: JSON string to parse
        default: Value to return on parse failure (default: None)

    Returns:
        Parsed JSON or default value
    """
    if not json_string:
        return default
    try:
        return json.loads(json_string)
    except (json.JSONDecodeError, TypeError):
        return default
