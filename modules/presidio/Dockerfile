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
# ON-DEMAND, single process: the backend `docker run`s this when it needs NER;
# server.py warms the model, serves, and exits itself when idle (PRESIDIO_IDLE_SECONDS)
# so the --rm container is removed. No gunicorn: one serial caller (the backend
# during report masking), and a single process is what can cleanly self-exit.
CMD ["python", "server.py"]
