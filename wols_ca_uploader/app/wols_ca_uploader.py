import sys
import logging

# 1. ENFORCE VERSION AT THE TOP
if sys.version_info < (3, 12):
    # We use print here because logging might not be configured yet
    print("FATAL: This addon requires Python 3.12 or higher.")
    print(f"Current version: {sys.version}")
    sys.exit(1)

import paho.mqtt.client as mqtt
import os
import yaml
import json
import traceback

from mqtt_triggers import handle_mqtt_message

# Global variable to hold the version across callbacks
current_version = "Unknown"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def get_version_from_yaml():
    """Reads version from the internal path defined in the Dockerfile."""
    version_file = "/app/internal/version.yaml"
    try:
        with open(version_file, "r") as f:
            data = yaml.safe_load(f)
        return data.get("version", "Unknown")
    except Exception as e:
        logging.error(f"Could not read version file: {e}")
        return "Unknown"

def get_mqtt_settings():
    """Reads settings from HA Options, mapping snake_case keys correctly."""
    config_file = "/data/options.json"
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)

        # Match keys defined in config.yaml schema
        broker = data.get("mqtt_broker", "localhost")
        port = data.get("mqtt_port", 1883)
        user = data.get("mqtt_user", None)
        password = data.get("mqtt_password", None)
        topic = data.get("mqtt_topic", None)

        logging.info(f"MQTT Settings - Broker: {broker}, Port: {port}, User: {user}, Topic: {topic}")
        return broker, port, user, password, topic
    except Exception as e:
        logging.error(f"Critical error loading /data/options.json: {e}")
        raise

def on_connect(client, userdata, flags, rc, properties=None):
    if reason_code == 0:
        logging.info("Connected successfully to MQTT broker (API v2).")
        # Subscribe to all relevant topics
        client.subscribe("wols-ca/trigger/#")
        client.subscribe("wols-ca/keys/public")
        client.subscribe("wols-ca/secrets/request/#")
        client.subscribe("wols-ca/uploader/required_version")
        
        # Publish current version on connect
        publish_version(client, current_version)
    else:
        logging.error(f"Connection failed with result code {reason_code}")

def on_message(client, userdata, msg):
    if not handle_mqtt_message(client, msg, current_version):
        logging.info(f"No handler for topic: {msg.topic}")

def publish_version(client, version):
    client.publish("wols-ca/uploader/version", version, retain=True)

def log_start_banner(version, broker, port, user, topic):
    border = "*" * 80
    logging.info(border)
    logging.info("WOLS CA Uploader - MQTT Client for Home Assistant Add-on")
    logging.info(border)
    logging.info(f"Version  : {version}")
    logging.info(f"Broker   : {broker}")
    logging.info(f"Port     : {port}")
    logging.info(f"User     : {user}") 
    logging.info(f"Topic    : {topic}")
    logging.info(border)

def main():
    global current_version
    try:
        current_version = get_version_from_yaml()
        broker, port, user, password, topic = get_mqtt_settings()

        log_start_banner(current_version, broker, port, user, topic)
        
        client = mqtt.Client()
        if user and password:
            client.username_pw_set(user, password)
            
        client.on_connect = on_connect
        client.on_message = on_message
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        
        logging.info(f"Attempting connection to {broker}...")
        client.connect(broker, port, 60)
        
        # Start the loop
        client.loop_forever()
        
    except Exception:
        logging.error("FATAL ERROR during startup:")
        logging.error(traceback.format_exc())
        exit(1)

if __name__ == "__main__":
    main()