import sys
import logging
import threading
import time
import os

# 1. ENFORCE VERSION AT THE TOP
if sys.version_info < (3, 12):
    print("FATAL: This addon requires Python 3.12 or higher.")
    print(f"Current version: {sys.version}")
    sys.exit(1)

import paho.mqtt.client as mqtt
import yaml
import json
import traceback

from mqtt_triggers import handle_mqtt_message, set_mqtt_credentials, publish_dashboard_discovery
from secrets_handler import get_secret

# Global variable to hold the version across callbacks
current_version = "Unknown"

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def start_heartbeat(client, interval=60):
    def heartbeat():
        while True:
            if client.is_connected():
                payload = json.dumps({
                    "status": "online",
                    "timestamp": int(time.time()),
                    "version": current_version
                })
                client.publish("wols-ca/uploader/status", payload, qos=1, retain=True)
            time.sleep(interval)
    threading.Thread(target=heartbeat, daemon=True).start()

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

        if not password:
            logging.info("MQTT password empty in options.json. Loading from secrets.yaml...")
            password = get_secret("mqtt_password")
        else:
            logging.info("MQTT password loaded directly from options.json.")

        set_mqtt_credentials(user, password)
        return broker, port, user, password, topic
    except Exception as e:
        logging.error(f"Critical error loading /data/options.json: {e}")
        raise

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info("Connected successfully to MQTT broker (API v2).")
        
        online_payload = json.dumps({
            "status": "online", 
            "version": current_version, 
            "timestamp": int(time.time())
        })
        client.publish("wols-ca/uploader/status", online_payload, qos=1, retain=True)

        client.subscribe([
            ("wols-ca/keys/public", 1),
            ("wols-ca/admin/password_ack", 1),
            ("wols-ca/trigger/#", 1),
            ("wols-ca/keys/raw_bytes", 1),
            ("wols-ca/uploader/required_version", 1),
            ("wols-ca/admin/command/#", 1),
            ("wols-ca/admin/set_secret/#", 1)
        ])  
        
        client.publish("wols-ca/admin/request_key", "STARTUP_SYNC")
        publish_version(client, current_version)
        
        # --- HIER WORDT HET DASHBOARD GEBOUWD BIJ OPSTARTEN ---
        publish_dashboard_discovery(client)
    else:
        logging.error(f"Connection failed with result code {reason_code}")

def on_message(client, userdata, msg):
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
    try:
        current_version = get_version_from_yaml()
        broker, port, user, password, topic = get_mqtt_settings()

        log_start_banner(current_version, broker, port, user, topic)
        
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
        
        if user and password:
            client.username_pw_set(user, password)
            
        death_payload = json.dumps({"status": "offline", "version": current_version})
        client.will_set("wols-ca/uploader/status", payload=death_payload, qos=1, retain=True)

        client.on_connect = on_connect
        client.on_message = on_message
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        
        logging.info(f"Attempting connection to {broker}...")
        client.connect(broker, port, 60)

        start_heartbeat(client) 
        
        client.loop_forever()
        
    except Exception:
        logging.error("FATAL ERROR during startup:")
        logging.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()