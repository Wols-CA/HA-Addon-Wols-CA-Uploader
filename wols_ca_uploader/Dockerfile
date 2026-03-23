# We gebruiken de officiële Python image in plaats van de HA-base om s6 te vermijden
FROM python:3.12-alpine

# Installeer de benodigde MQTT library
RUN pip install --no-cache-dir paho-mqtt

# Map aanmaken voor de app
WORKDIR /app

# Kopieer het script
COPY wols_ca_uploader.py .

# CRUCIAL: Hiermee vertellen we HA dat we GEEN s6-overlay willen gebruiken
ENV S6_SERVICES_GRACETIME=0
ENV S6_READ_ONLY_ROOT=1

# Start het script direct
ENTRYPOINT ["python", "wols_ca_uploader.py"]
