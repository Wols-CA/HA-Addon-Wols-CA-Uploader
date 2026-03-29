FROM python:3.12-alpine

# Force logs to show up immediately
ENV PYTHONUNBUFFERED=1

# Copy requirements first
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set working directory
WORKDIR /app

# Copy Python source files
COPY app/wols_ca_uploader.py .
COPY app/mqtt_triggers.py .
COPY app/public_key_handler.py .
COPY app/secrets_handler.py .

# Setup internal config path
RUN mkdir -p /app/internal
COPY config/version.yaml /app/internal/version.yaml

ENTRYPOINT ["python", "wols_ca_uploader.py"]