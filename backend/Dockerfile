# Build context is the repository root (so EVALS.md and the committed data snapshot are available):
#   docker build -f backend/Dockerfile .
FROM python:3.12-slim
WORKDIR /app
RUN useradd --create-home --uid 10001 app
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY backend/blastradius ./blastradius
COPY backend/evals ./evals
COPY backend/snapshot ./snapshot
COPY EVALS.md /EVALS.md
ENV FALKOR_HOST=falkordb BR_SNAPSHOT_DIR=/app/snapshot BR_CACHE_DIR=/app/.cache PYTHONUNBUFFERED=1
RUN mkdir -p /app/.cache && chown -R app /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/api/health').status==200 else 1)"
CMD ["uvicorn", "blastradius.api:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
