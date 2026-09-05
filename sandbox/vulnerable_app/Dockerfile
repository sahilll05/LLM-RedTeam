# syntax=docker/dockerfile:1
# ── VAJRA Sandbox: Deliberately-Vulnerable Flask App ──────────────────────────
#
# This container intentionally runs an insecure Flask application for use
# ONLY within VAJRA's sandboxed exploit verification pipeline.
# It is network-isolated via docker-compose and must NEVER be exposed
# to a public network. See sandbox/docker-compose.yml for isolation config.

FROM python:3.11-slim

LABEL org.opencontainers.image.title="VAJRA Sandbox"
LABEL org.opencontainers.image.description="Deliberately-vulnerable SQLi target for exploit verification"
LABEL org.opencontainers.image.source="https://github.com/sahilll05/LLM-RedTeam"

# Security: run as non-root
RUN adduser --disabled-password --gecos "" sandboxuser

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Database in /tmp — ephemeral, reset on container restart
ENV DB_PATH=/tmp/vajra_sandbox.db
ENV FLASK_ENV=production

USER sandboxuser

EXPOSE 5555

# Initialise DB then start Flask
CMD ["python", "-c", "import app; app.init_db(); app.app.run(host='0.0.0.0', port=5555, debug=False)"]
