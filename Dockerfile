# ── Stage 1: builder ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /app

# Instalar deps en un prefix aislado para copiar solo lo necesario al runtime.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Usuario no-root (buena práctica de seguridad de contenedor).
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Copiar las deps ya instaladas desde el builder.
COPY --from=builder /install /usr/local

# Copiar solo el código de la app.
COPY app.py .

USER appuser

EXPOSE 5000

ENV PYTHONUNBUFFERED=1 \
    PORT=5000

# Healthcheck para Docker y orquestadores.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request, sys; \
sys.exit(0 if urllib.request.urlopen('http://localhost:5000/health', timeout=3).status == 200 else 1)"

# En producción se usa gunicorn (Flask dev server no es apto).
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "app:create_app()"]
