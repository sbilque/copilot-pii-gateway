# Image commune du lab : passerelle, faux serveur Copilot, PKI et tests.
FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
# nftables : verification du verrou reseau (J7, service lock).
RUN apt-get update && apt-get install -y --no-install-recommends nftables \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --system --uid 10001 lab \
    && useradd --system --uid 10002 gateway \
    && mkdir /pki /recordings /hot && chown lab /pki /recordings /hot
USER lab
