ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base:latest
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip
RUN pip3 install paho-mqtt --break-system-packages

WORKDIR /app
COPY wols_ca_uploader.py .

# We omzeilen s6 door python direct als init te draaien
CMD ["python3", "/app/wols_ca_uploader.py"]
