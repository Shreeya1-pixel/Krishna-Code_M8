# M8 — single service for Railway / Docker
# Builds React UI, then serves API + static files from FastAPI.

FROM node:20-bookworm AS frontend
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm install
COPY frontend/ ./
# Same-origin API in production (empty base URL)
ENV VITE_API_URL=
RUN npm run build

FROM python:3.11-slim-bookworm
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

COPY backend/ ./backend/
# Ensure package imports work
RUN touch backend/__init__.py \
 && touch backend/agent/__init__.py \
 && touch backend/attacks/__init__.py \
 && touch backend/defenses/__init__.py \
 && touch backend/scoring/__init__.py \
 && touch backend/store/__init__.py \
 && touch backend/workflow/__init__.py \
 && touch backend/reports/__init__.py \
 && mkdir -p backend/defenses/ml && touch backend/defenses/ml/__init__.py \
 && mkdir -p backend/workflow/integrations && touch backend/workflow/integrations/__init__.py

COPY --from=frontend /frontend/dist ./frontend/dist

ENV LLM_PROVIDER=mock
ENV SENTINEL_SEED_BASELINE=false
ENV SENTINEL_DB_PATH=/tmp/sentinel.db
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["sh", "-c", "uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
