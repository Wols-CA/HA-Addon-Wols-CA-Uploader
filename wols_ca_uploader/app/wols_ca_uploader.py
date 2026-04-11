import sys
import logging
import threading
import time
import os
import json
import traceback
import hashlib

# 1. ENFORCE VERSION
if sys.version_info < (3, 12):
    sys.exit(1)

import yaml
import paho.mqtt.client as mqtt

# Local module imports
# In wols_ca_uploader.py
from mqtt_triggers import (
    handle_mqtt_message, 
    set_mqtt_credentials, 
    publish_dashboard_discovery, 
    MQTTMessageRouter  # <--- Deze moet erbij!
)
from secrets_handler import get_secret
import public_key_handler

current_version = "Unknown"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def get_scrambled_path(mailbox_id, sub_topic):
    """Sync met C++ GlobalUtilities SHA256 logic [cite: 2026-04-09]."""
    mb_hash = hashlib.sha256(mailbox_id.encode()).hexdigest()[:16]
    sub_hash = hashlib.sha256(sub_topic.encode()).hexdigest()[:16]
    return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}"

def start_heartbeat(client, mailbox_id, interval=60):
    def heartbeat():
        while True:
            if client.is_connected():
                payload = json.dumps({
                    "status": "online",
                    "timestamp": int(time.time()),
                    "version": current_version
                })
                # Heartbeat naar de beveiligde status-mailbox (GEEN retain) [cite: 2026-04-09]
                topic = get_scrambled_path(mailbox_id, "uploader_status")
                client.publish(topic, payload, qos=0, retain=False)
            time.sleep(interval)
    threading.Thread(target=heartbeat, daemon=True).start()

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info("Connected to Wols CA MQTT Broker.")
        
        # Gebruik de MailboxID uit de userdata of config
        options = userdata.get('options', {})
        m_id = options.get("WolsCA_MailboxID", "88889999")

        # 1. Subscribe op de 'Troebele' Handshake kanalen [cite: 2026-04-09]
        client.subscribe([
            ("wols_ca_mqtt/keys/public", 1),
            ("wols_ca_mqtt/admin/password_ack", 1),
            (get_scrambled_path(m_id, "key_rotation"), 1), # Trap 2/3 van de raket
            (get_scrambled_path(m_id, "requests"), 1)      # Inkomende post
        ])  
        
        # 2. Vraag de eerste sleutel aan (Bootstrap)
        client.publish("wols_ca_mqtt/admin/request_key", "STARTUP_SYNC")
        publish_dashboard_discovery(client)

def main():
    global current_version
    try:
        current_version = "0.1.6"
        config_file = "/data/options.json"
        
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                options = json.load(f)
        else:
            options = {}

        broker = options.get("mqtt_broker", "localhost")
        port = options.get("mqtt_port", 1883)
        user = options.get("mqtt_user")
        password = options.get("mqtt_password") or get_secret("mqtt_password")
        
        set_mqtt_credentials(user, password)

        # 1. FORCEER INITIALISATIE VAN DE ROUTER
        # Nu MQTTMessageRouter is geïmporteerd, kan deze aangemaakt worden
        import mqtt_triggers
        mqtt_triggers._router_instance = MQTTMessageRouter(current_version)
        
        # 2. Configureer de MQTT Client
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, userdata={'options': options})
        
        if user and password:
            client.username_pw_set(user, password)

        client.on_connect = on_connect
        client.on_message = lambda c, u, m: handle_mqtt_message(c, m, current_version)
        
        logging.info(f"Connecting to {broker} via Mailbox {options.get('WolsCA_MailboxID', '88889999')}...")
        client.connect(broker, port, 60)

        # Gebruik de mailbox ID voor de heartbeat status
        start_heartbeat(client, options.get("WolsCA_MailboxID", "88889999")) 
        
        client.loop_forever()
        
    except Exception as e:
        logging.error(f"FATAL ERROR during startup: {e}")
        logging.error(traceback.format_exc())
        sys.exit(1)
if __name__ == "__main__":
    main()