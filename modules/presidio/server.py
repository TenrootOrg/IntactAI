"""Intact PII NER sidecar — a tiny REST front end over Presidio's AnalyzerEngine.

WHY A SIDECAR. The deterministic DataAnonymizer (in the backend) owns the
structured forensic identifiers; this service only does the NER second pass that
catches free-text leftovers (person/company names) regex cannot. It lives in its
own container — like Velociraptor, ELK, VolWeb — so the ~1 GB spaCy model and its
RAM stay OUT of the backend image/process, and the model is BAKED IN at build
time (CI has internet); at runtime this never reaches the internet.

CONTRACT (what the backend's services/presidio_masker.py calls):
  GET  /health                 -> {"status":"ok","model":"<name>"}  200, else 503
  POST /analyze  {text, entities?, score_threshold?, language?}
                               -> {"spans":[{entity_type,start,end,score}, ...]}
The backend does all masking/pseudonymisation/reversibility itself from these
spans — this service returns ONLY the detected offsets, never stores anything.
"""
import os
import threading
import time

from flask import Flask, jsonify, request

APP = Flask(__name__)
_ENGINE = None
_MODEL = None

# ON-DEMAND LIFECYCLE (like plaso/log2timeline). The backend starts this
# container only when it needs the NER pass; the container then exits itself once
# no request has arrived for PRESIDIO_IDLE_SECONDS, so it is "active only while
# used, then off". 0 disables the self-shutdown (dev).
_LAST_REQUEST = time.time()
IDLE_SECONDS = int(os.environ.get("PRESIDIO_IDLE_SECONDS", "180"))


@APP.before_request
def _touch_idle_timer():
    global _LAST_REQUEST
    _LAST_REQUEST = time.time()


def _idle_watchdog():
    while True:
        time.sleep(15)
        if IDLE_SECONDS > 0 and (time.time() - _LAST_REQUEST) > IDLE_SECONDS:
            os._exit(0)   # process exits -> the --rm container is removed -> "off"


def _engine():
    """Build the AnalyzerEngine once (slow: loads the spaCy model)."""
    global _ENGINE, _MODEL
    if _ENGINE is not None:
        return _ENGINE
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider
    # The model is whatever CI baked in; try biggest-first so the image's choice wins.
    want = os.environ.get("PRESIDIO_MODEL", "")
    order = [want] if want else []
    order += ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]
    last = None
    for model in [m for m in order if m]:
        try:
            prov = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": model}],
            })
            _ENGINE = AnalyzerEngine(nlp_engine=prov.create_engine(),
                                     default_score_threshold=0.0)
            _MODEL = model
            return _ENGINE
        except Exception as e:                         # noqa: BLE001 — try the next model
            last = e
    raise RuntimeError(f"no spaCy model available: {last}")


@APP.get("/health")
def health():
    try:
        _engine()
        return jsonify({"status": "ok", "model": _MODEL}), 200
    except Exception as e:                             # noqa: BLE001
        return jsonify({"status": "unavailable", "error": str(e)[:200]}), 503


@APP.post("/analyze")
def analyze():
    body = request.get_json(silent=True) or {}
    text = body.get("text")
    if not isinstance(text, str) or not text:
        return jsonify({"spans": []})
    entities = body.get("entities") or ["PERSON", "ORG"]
    threshold = float(body.get("score_threshold", 0.6))
    language = body.get("language", "en")
    try:
        results = _engine().analyze(text=text, entities=list(entities), language=language)
    except Exception as e:                             # noqa: BLE001
        return jsonify({"error": str(e)[:200], "spans": []}), 500
    spans = [{"entity_type": r.entity_type, "start": r.start, "end": r.end,
              "score": round(float(r.score), 4)}
             for r in results if r.score >= threshold]
    return jsonify({"spans": spans})


if __name__ == "__main__":
    # The container's entry point (Dockerfile CMD). Warm the model so the first
    # request isn't slow, start the idle watchdog so the container turns itself
    # off when unused, then serve.
    _engine()
    threading.Thread(target=_idle_watchdog, daemon=True).start()
    APP.run(host="0.0.0.0", port=int(os.environ.get("PORT", "3000")))
