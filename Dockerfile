# Use Python 3.12 Alpine image as base
FROM python:3.12-alpine3.20

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py \
    FLASK_ENV=production

# Install system dependencies (use HTTP to avoid SSL issues with corporate proxies)
RUN sed -i 's/https/http/' /etc/apk/repositories && \
    apk add --no-cache \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Create directory for SQLite database
RUN mkdir -p instance && chmod 777 instance

# Create a non-root user and switch to it
RUN adduser -D appuser && chown -R appuser:appuser /app
USER appuser

# Expose port
EXPOSE 5000

# Run the application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "pwd_manager:create_app()", "--reload"]
