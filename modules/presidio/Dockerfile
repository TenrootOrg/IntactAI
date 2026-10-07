# Intact PII NER sidecar — Presidio AnalyzerEngine behind a tiny REST API.
# Built by CI (build-release-assets.yml) and shipped in the offline bundle, so the
# spaCy model is downloaded HERE, at build time (CI has internet), and baked into
# the image. At runtime the container never reaches the internet.
FROM python:3.11-slim

# Which spaCy model to bake in. lg = best recall (recommended, ~560MB on disk,
# ~740MB RAM); md = lighter (~40MB / ~360MB RAM, same result on typical payloads).
# No GPU anywhere, so the transformer model is intentionally NOT an option.
ARG PRESIDIO_MODEL=en_core_web_lg
ENV PRESIDIO_MODEL=${PRESIDIO_MODEL}

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m spacy download ${PRESIDIO_MODEL}

COPY server.py .

EXPOSE 3000
# Warm the model at boot (first request otherwise pays the ~2s load); 2 workers,
# long timeout because a large payload's NER pass can take a couple of seconds.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=5 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:3000/health',timeout=5).status==200 else 1)"
CMD ["gunicorn", "--bind", "0.0.0.0:3000", "--workers", "2", "--timeout", "120", \
     "--preload", "--access-logfile", "-", "server:APP"]
