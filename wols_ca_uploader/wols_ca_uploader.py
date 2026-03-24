import paho.mqtt.client as mqtt
import json
import base64
import os
import sys
import time
import logging
from collections import defaultdict

# --- LOGGER SETUP ---
logging.basicConfig(
    format='%(asctime)s %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# --- HA OPTIONS LOADER ---
OPTIONS_PATH = "/data/options.json"
if os.path.exists(OPTIONS_PATH):
    with open(OPTIONS_PATH) as f:
        conf = json.load(f)
else:
    conf = {}

MQTT_BROKER = conf.get("mqtt_broker", "192.168.101.240")
MQTT_PORT = conf.get("mqtt_port", 1883)
MQTT_USER = conf.get("mqtt_user", "")
MQTT_PASS = conf.get("mqtt_password", "")
MQTT_TOPIC = conf.get("mqtt_topic", "wols-ca/admin/automation_upload")
AUTOMATIONS_DIR = "/config/automations"

parts_buffer = defaultdict(dict)
current_versions = {}
failed_attempts = 0

def on_connect(client, userdata, flags, rc, properties=None):
    global failed_attempts
    if rc == 0:
        logger.info(f"CONNECTED to {MQTT_BROKER} as {MQTT_USER}")
        failed_attempts = 0
        client.subscribe(MQTT_TOPIC)
        logger.info(f"SUBSCRIBED to topic: {MQTT_TOPIC}")
    else:
        failed_attempts += 1
        logger.error(f"AUTH FAILED for {MQTT_USER} (Code: {rc})")

def on_message(client, userdata, msg):
    logger.info(f"MESSAGE received on {msg.topic}")
    try:
        payload = json.loads(msg.payload.decode())
        filename = payload["filename"]
        version = payload["version"]
        part = payload["part"]
        total_parts = payload["total_parts"]
        data = base64.b64decode(payload["data"])

        key = (filename, version)
        parts_buffer[key][part] = data

        if len(parts_buffer[key]) == total_parts:
            full_content = b''.join(parts_buffer[key][i] for i in range(1, total_parts + 1))
            
            if not os.path.exists(AUTOMATIONS_DIR):
                os.makedirs(AUTOMATIONS_DIR)

            with open(os.path.join(AUTOMATIONS_DIR, filename), "w") as f:
                f.write(full_content.decode('utf-8'))
            
            logger.info(f"INSTALLED: {filename} (v{version})")
            current_versions[filename] = version
            del parts_buffer[key]
    except Exception as e:
        logger.error(f"PROCESSING ERROR: {e}")

# --- SETUP ---
client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

if MQTT_USER and MQTT_PASS:
    client.username_pw_set(MQTT_USER, MQTT_PASS)

logger.info("STARTING Uploader Service...")

# --- MAIN LOOP ---
while True:
    try:
        logger.info(f"CONNECTING to {MQTT_BROKER}:{MQTT_PORT}...")
        client.connect(MQTT_BROKER, MQTT_PORT, 60)
        client.loop_forever() 
    except Exception as e:
        failed_attempts += 1
        logger.error(f"NETWORK ERROR: {e}")
    
    # Bepaal wachttijd
    sleep_time = 300 if failed_attempts >= 5 else 15
    logger.info(f"WAITING {sleep_time} seconds before retry...")
    time.sleep(sleep_time)
