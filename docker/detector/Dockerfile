FROM python:3.12.8-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY requirements-detector.txt requirements-gnn.txt /tmp/
RUN pip install -r /tmp/requirements-detector.txt \
 && pip install -r /tmp/requirements-gnn.txt --index-url https://download.pytorch.org/whl/cpu \
 && apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# O codigo e montado em /app pelo docker compose (volume), garantindo que o
# commit registrado em environment.json corresponde ao codigo executado.
CMD ["python", "-m", "ips.detector"]
