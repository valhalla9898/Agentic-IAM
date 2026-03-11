# Agentic-IAM Production Dockerfile
# Multi-stage build for optimized production image

# Build stage
FROM python:3.11-slim as builder

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Create and activate virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Production stage
FROM python:3.11-slim as production

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    AGENTIC_IAM_ENVIRONMENT=production

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd -r agentic && useradd -r -g agentic -d /app -s /bin/bash agentic

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv

# Create application directory
WORKDIR /app

# Copy application code
COPY --chown=agentic:agentic . .

# Create necessary directories
RUN mkdir -p /app/logs /app/data/agents /app/data/credentials /app/data/audit && \
    chown -R agentic:agentic /app

# Create startup script
RUN cat > /app/docker-entrypoint.sh << 'EOF'
#!/bin/bash
set -e

# Function to wait for database
wait_for_db() {
    echo "Waiting for database connection..."
    until python -c "
import sys
import os
from urllib.parse import urlparse
database_url = os.getenv('AGENTIC_IAM_DATABASE_URL', 'sqlite:///agentic_iam.db')
if 'postgresql' in database_url:
    import psycopg2
    url = urlparse(database_url)
    try:
        conn = psycopg2.connect(
            database=url.path[1:] if url.path else 'agentic_iam',
            user=url.username or 'agentic_user',
            password=url.password or '',
            host=url.hostname or 'localhost',
            port=url.port or 5432
        )
        conn.close()
        print('Database is ready!')
    except Exception as e:
        exit(1)
else:
    print('SQLite mode - database ready!')
" 2>/dev/null; do
        echo "Database is unavailable - sleeping"
        sleep 2
    done
}

# Wait for PostgreSQL if configured
if echo "${AGENTIC_IAM_DATABASE_URL:-}" | grep -q "postgresql"; then
    wait_for_db
fi

echo "Starting Agentic-IAM application..."
# Execute the main command
exec "$@"
EOF

RUN chmod +x /app/docker-entrypoint.sh

# Switch to non-root user
USER agentic

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose ports
EXPOSE 8000 8501

# Set default command
ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["python", "main.py"]

# Labels for metadata
LABEL maintainer="Agentic-IAM Team" \
      version="1.0.0" \
      description="Agentic Identity & Access Management Platform" \
      org.opencontainers.image.source="https://github.com/your-org/agentic-iam-python" \
      org.opencontainers.image.title="Agentic-IAM" \
      org.opencontainers.image.description="Production-ready Agent Identity & Access Management Platform" \
      org.opencontainers.image.version="1.0.0"