# MetaSight backend — dev-oriented image (used by ../docker-compose.yml).
#
# This is NOT the hardened production deploy path — for bare-metal/VM
# production (systemd, gunicorn, nginx/TLS, hardening checklist), see
# ../DEPLOYMENT.md. This image favors a fast, correct local `docker compose
# up` over minimal image size or production process management.
FROM python:3.11-slim

# build-essential + libpq-dev: most of requirements.txt's DB drivers ship
# manylinux wheels and don't need this, but a couple of transitive deps
# don't always publish one for every platform/Python combination — cheap
# insurance against an obscure "no wheel, compiling from source" failure.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN chmod +x docker-entrypoint.sh

EXPOSE 8000

ENTRYPOINT ["./docker-entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
