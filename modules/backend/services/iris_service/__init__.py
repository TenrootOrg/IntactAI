"""IRIS integration package — split from the former iris_service.py.
Public import path unchanged: `from services.iris_service import import_to_iris` works.
  _iocs.py — IOC extraction/formatting/merging (parse report + summaries + timeline).
  _api.py  — IRIS REST ops (case/asset/timeline/ioc/asset push) + import_to_iris orchestrator.
"""
from services.iris_service._iocs import *  # noqa: F401,F403
from services.iris_service._api import *    # noqa: F401,F403
