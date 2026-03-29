import sys
import logging

# 1. ENFORCE VERSION AT THE TOP
if sys.version_info < (3, 12):
    print("FATAL: This addon requires Python 3.12 or higher.")
    print(f"Current version: {sys.version}")
    sys.exit(1)

import paho.mqtt.client as mqtt
import yaml
import json
import traceback

from mqtt_triggers import handle_mqtt_message
# Note: We don't need to import active_public_key here anymore 
# because mqtt_triggers and public_key_handler handle the logic.

# Global variable to hold the version across callbacks
current_version = "Unknown"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def get_version_from_yaml():
    version_file = "/app/internal/version.yaml"
    try:
        with open(version_file, "r") as f:
            data = yaml.safe_load(f)
        return data.get("version", "Unknown")
    except Exception as e:
        logging.error(f"Could not read version file: {e}")
        return "Unknown"

def get_mqtt_settings():
    config_file = "/data/options.json"
    try:
        with open(config_file, 'r') as f:
            data = json.load(f)
        broker = data.get("mqtt_broker", "localhost")
        port = data.get("mqtt_port", 1883)
        user = data.get("mqtt_user", None)
        password = data.get("mqtt_password", None)
        topic = data.get("mqtt_topic", None)
        return broker, port, user, password, topic
    except Exception as e:
        logging.error(f"Critical error loading /data/options.json: {e}")
        raise

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info("Connected successfully to MQTT broker (API v2).")

        # 1. Subscriptions
        client.subscribe([
            ("wols-ca/keys/public", 1),          # Hear the new key from C++
            ("wols-ca/admin/password_ack", 1),   # Hear the 'OK' from C++
            ("wols-ca/trigger/#", 1),            # Hear HA automation commands
            ("wols-ca/keys/raw_bytes", 1),       # Hear the raw byte array for the key
            ("wols-ca/uploader/required_version", 1) # Hear version requirements
        ])  
        # 2. Proactively request a key pair
        client.publish("wols-ca/admin/request_key", "STARTUP_SYNC")

        # 3. Publish current version
        publish_version(client, current_version)
    else:
        logging.error(f"Connection failed with result code {reason_code}")

def on_message(client, userdata, msg):
    # Pass off to our trigger handler
    if not handle_mqtt_message(client, msg, current_version):
        logging.debug(f"No specific handler for topic: {msg.topic}")

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
    # REMOVED: active_public_key/temp_public_key local definitions here.
    # These are handled globally within public_key_handler.py.

    try:
        current_version = get_version_from_yaml()
        broker, port, user, password, topic = get_mqtt_settings()

        log_start_banner(current_version, broker, port, user, topic)
        
        # Using CallbackAPIVersion.VERSION2 for paho-mqtt 2.x
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        
        if user and password:
            client.username_pw_set(user, password)
            
        client.on_connect = on_connect
        client.on_message = on_message
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        
        logging.info(f"Attempting connection to {broker}...")
        client.connect(broker, port, 60)
        client.loop_forever()
        
    except Exception:
        logging.error("FATAL ERROR during startup:")
        logging.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()