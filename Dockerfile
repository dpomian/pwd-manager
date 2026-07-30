# Use Python 3.12 Alpine image as base
FROM python:3.12-alpine3.20

# Copy uv binary from official distroless image
COPY --from=ghcr.io/astral-sh/uv:0.5.20 /uv /uvx /bin/

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv

ENV PATH="/app/.venv/bin:$PATH"

# Install runtime dependencies (use HTTP for apk to avoid CA issues, then install certs)
RUN sed -i 's/https/http/' /etc/apk/repositories && \
    apk add --no-cache ca-certificates libffi openssl && \
    update-ca-certificates

# Copy dependency metadata first to leverage Docker cache
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --frozen --no-dev --no-install-project

# Copy project files and install the application
COPY . .
RUN uv sync --frozen --no-dev

# Create directory for SQLite database and attachments
RUN mkdir -p /app/instance && chmod 777 /app/instance

# Create a non-root user and switch to it
RUN adduser -D appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Run the application
CMD ["start", "--workers", "4", "--threads", "4"]
