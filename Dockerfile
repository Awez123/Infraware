FROM python:3.9-slim

# Set metadata
LABEL maintainer="InfraWare Team <team@infraware.dev>"
LABEL description="Enterprise Infrastructure Security & Cost Platform"
LABEL version="2.0.0"

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Install InfraWare
RUN pip install -e .

# Create directories for data
RUN mkdir -p /opt/infraware/rules \
    /opt/infraware/ignores \
    /opt/infraware/cache \
    /workspace

# Set environment variables
ENV INFRAWARE_DB_PATH=/opt/infraware/cve_database.db
ENV INFRAWARE_RULES_DIR=/opt/infraware/rules
ENV INFRAWARE_IGNORE_DIR=/opt/infraware/ignores
ENV INFRAWARE_CACHE_DIR=/opt/infraware/cache
ENV PYTHONUNBUFFERED=1

# Create non-root user
RUN useradd --create-home --shell /bin/bash infraware && \
    chown -R infraware:infraware /opt/infraware /workspace

# Switch to non-root user
USER infraware

# Set default working directory for mounted volumes
WORKDIR /workspace

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD infraware --version || exit 1

# Default command
ENTRYPOINT ["infraware"]
CMD ["--help"]