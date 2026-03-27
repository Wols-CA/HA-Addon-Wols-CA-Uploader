FROM python:3.12-alpine

# Copy requirements.txt first for better build caching
COPY requirements.txt .

# Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set working directory for app
WORKDIR /app

# Copy Python source files into /app
COPY app/wols_ca_uploader.py .
COPY app/mqtt_triggers.py .
COPY app/public_key_handler.py .
COPY app/secrets_handler.py .

# Copy config files into /config
RUN mkdir -p /config
COPY config/version.yaml /config/version.yaml

# Home Assistant s6-overlay settings
ENV S6_SERVICES_GRACETIME=0
ENV S6_READ_ONLY_ROOT=1

ENTRYPOINT ["python", "wols_ca_uploader.py"]