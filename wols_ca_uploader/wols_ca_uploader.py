import paho.mqtt.client as mqtt
import json
import base64
import os
import sys
from collections import defaultdict

# --- HA OPTIONS LOADER ---
# Home Assistant zet de opties in /data/options.json
OPTIONS_PATH = "/data/options.json"

if os.path.exists(OPTIONS_PATH):
    with open(OPTIONS_PATH) as f:
        conf = json.load(f)
else:
    print("❌ No options.json found, using defaults.")
    conf = {}

MQTT_BROKER = conf.get("mqtt_broker", "192.168.101.240")
MQTT_PORT = conf.get("mqtt_port", 1883)
MQTT_USER = conf.get("mqtt_user", "wols-ca-admin")
MQTT_PASS = conf.get("mqtt_password", "")
MQTT_TOPIC = conf.get("mqtt_topic", "wols-ca/admin/automation_upload")
AUTOMATIONS_DIR = "/config/automations"

parts_buffer = defaultdict(dict)
current_versions = {}

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        print(f"✅ Connected successfully to {MQTT_BROKER}")
        client.subscribe(MQTT_TOPIC)
        print(f"📡 Subscribed to: {MQTT_TOPIC}")
    else:
        print(f"❌ Connection failed! Reason code: {reason_code}")

def on_message(client, userdata, msg):
    print(f"📩 New message on {msg.topic}")
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
            
            print(f"🚀 Installed {filename} (v{version})")
            current_versions[filename] = version
            del parts_buffer[key]
    except Exception as e:
        print(f"🔥 Error: {e}")

client = mqtt.Client(callback_api_version=mqtt.CallbackAPIVersion.VERSION2)
client.on_connect = on_connect
client.on_message = on_message

# Gebruik User/Pass als deze zijn ingevuld
if MQTT_USER and MQTT_PASS:
    client.username_pw_set(MQTT_USER, MQTT_PASS)

print(f"🚀 Starting Service. Connecting to {MQTT_BROKER}...")

try:
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    client.loop_forever()
except Exception as e:
    print(f"💥 Connect Error: {e}")
    sys.exit(1)
