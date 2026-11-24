# ============================================================
# College Club Membership Portal — Dockerfile
# ============================================================
# Multi-stage build to keep the final image lean.

# ---- Stage 1: build dependencies ----
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools needed for some packages (e.g. cryptography)
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
    && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ---- Stage 2: runtime image ----
FROM python:3.11-slim AS runtime

LABEL maintainer="capstone-team"
LABEL description="College Club Membership Portal with Security Testing Dashboard"

# Non-root user for security
RUN groupadd -r appgroup && useradd -r -g appgroup appuser

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY . .

# Create the SQLite instance directory and set ownership
RUN mkdir -p /app/instance \
    && chown -R appuser:appgroup /app

USER appuser

# Expose the Flask port
EXPOSE 5000

# Environment defaults (override at runtime via -e or docker-compose)
ENV FLASK_ENV=production \
    FLASK_HOST=0.0.0.0 \
    FLASK_PORT=5000 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check — hits the login page
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/auth/login')" || exit 1

# Seed the DB then start the server
CMD ["sh", "-c", "python seed.py && python run.py"]
