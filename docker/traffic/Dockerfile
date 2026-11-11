FROM python:3.12.8-slim
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
RUN pip install requests==2.31.0  # benign.py; demais scripts usam http.client
WORKDIR /opt/traffic
COPY *.py ./
