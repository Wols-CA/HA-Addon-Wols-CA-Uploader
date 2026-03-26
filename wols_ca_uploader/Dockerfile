FROM python:3.12-alpine

# Copy requirements.txt first for better build caching
COPY requirements.txt .

# Install all Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

WORKDIR /app

# Copy your Python script(s) into the container
COPY wols_ca_uploader.py .

# (Optional) Copy other needed files, e.g. version.yaml, handler modules, etc.
# COPY version.yaml .
# COPY mqtt_triggers.py .
# COPY public_key_handler.py .
# COPY secrets_handler.py .

# Home Assistant s6-overlay settings
ENV S6_SERVICES_GRACETIME=0
ENV S6_READ_ONLY_ROOT=1

ENTRYPOINT ["python", "wols_ca_uploader.py"]
