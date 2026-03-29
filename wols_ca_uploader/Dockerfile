FROM python:3.12-alpine

# Force logs to show up immediately in HA
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt [cite: 4]

WORKDIR /app

# Copy app files 
COPY app/wols_ca_uploader.py .
COPY app/mqtt_triggers.py .
COPY app/public_key_handler.py .
COPY app/secrets_handler.py .

# Move version.yaml to an internal app path to avoid /config mount issues
RUN mkdir -p /app/internal
COPY config/version.yaml /app/internal/version.yaml 

ENTRYPOINT ["python", "wols_ca_uploader.py"]