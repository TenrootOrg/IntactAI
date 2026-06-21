"""Agentic collectors package — split from the former collectors.py.
Public import path unchanged: `from services.agentic.collectors import X` works
(incl. api_pb2 / api_pb2_grpc re-exported for velociraptor_service).
  _base.py   — flow status, time-range, VQL/artifact spec, hostname resolution,
               collection create/enumerate/query, severity filter, cancel,
               existing-collection retrieval.
  _stream.py — stream_collect_and_analyze (the large streaming orchestrator).
"""
from services.agentic.collectors._base import *    # noqa: F401,F403
from services.agentic.collectors._stream import *  # noqa: F401,F403
