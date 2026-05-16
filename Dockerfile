# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

COPY --from=builder /install /usr/local

COPY app.py .

USER appuser

EXPOSE 5000

ENV PYTHONUNBUFFERED=1 \
    PORT=5000


HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:' + __import__('os').environ.get('PORT','5000') + '/', timeout=3).status==200 else 1)"

CMD gunicorn --bind 0.0.0.0:${PORT:-5000} --workers 2 "app:create_app()"
