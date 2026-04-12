import sys
import logging
import threading
import time
import os
import json
import traceback
import hashlib

# 1. ENFORCE VERSION AT THE TOP
if sys.version_info < (3, 12):
    print("FATAL: This addon requires Python 3.12 or higher.")
    print(f"Current version: {sys.version}")
    sys.exit(1)

import yaml
import paho.mqtt.client as mqtt

# Local module imports
from mqtt_triggers import (
    handle_mqtt_message, 
    set_mqtt_credentials, 
    publish_dashboard_discovery, 
    MQTTMessageRouter,
    get_scrambled_path_helper
)
from secrets_handler import get_secret

current_version = "Unknown"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

def start_heartbeat(client, mailbox_id, interval=60):
    def heartbeat():
        while True:
            if client.is_connected():
                payload = json.dumps({
                    "status": "online",
                    "timestamp": int(time.time()),
                    "version": current_version
                })
                # Heartbeat naar de beveiligde status-mailbox (GEEN retain)
                topic = get_scrambled_path_helper(mailbox_id, "uploader_status")
                client.publish(topic, payload, qos=0, retain=False)
            time.sleep(interval)
    threading.Thread(target=heartbeat, daemon=True).start()

def get_version_from_yaml():
    version_file = "/app/internal/version.yaml"
    try:
        with open(version_file, "r") as f:
            data = yaml.safe_load(f)
        return data.get("version", "Unknown")
    except Exception as e:
        return "0.1.6"

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info("Connected to Wols CA MQTT Broker.")
        options = userdata.get('options', {})
        m_id = options.get("WolsCA_MailboxID", "88889999")

        # 1. Bepaal de hash voor de brievenbus
        import hashlib
        mb_hash = hashlib.sha256(str(m_id).encode()).hexdigest()[:16]

        # 2. Subscribe op de 'Troebele' kanalen, de Wols CA Handshake én de HA UI commando's
        client.subscribe([
            ("wols_ca_mqtt/keys/public", 1),
            ("wols_ca_mqtt/admin/service_verify", 1), 
            ("wols_ca_mqtt/admin/password_ack", 1),
            (get_scrambled_path_helper(m_id, "key_rotation"), 1),
            (get_scrambled_path_helper(m_id, "requests"), 1),
            (f"wols_ca_mqtt/mb/{mb_hash}/+/set/#", 1)  # Luister naar de HA invoer!
        ])  
        
        # 3. Vraag de eerste sleutel aan op de JUISTE root
        client.publish("wols_ca_mqtt/admin/request_key", "STARTUP_SYNC", retain=False)
        
        # 4. Bouw het dashboard
        publish_dashboard_discovery(client)
    else:
        logging.error(f"Connection failed with result code {reason_code}")

def main():
    global current_version
    try:
        current_version = get_version_from_yaml()
        config_file = "/data/options.json"
        
        options = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                options = json.load(f)

        broker = options.get("mqtt_broker", "localhost")
        port = options.get("mqtt_port", 1883)
        user = options.get("mqtt_user")
        password = options.get("mqtt_password") or get_secret("mqtt_password")
        
        set_mqtt_credentials(user, password)

        # FORCEER INITIALISATIE VAN DE ROUTER
        import mqtt_triggers
        mqtt_triggers._router_instance = MQTTMessageRouter(current_version)

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, userdata={'options': options})
        
        if user and password:
            client.username_pw_set(user, password)

        client.on_connect = on_connect
        client.on_message = lambda c, u, m: handle_mqtt_message(c, m, current_version)
        client.reconnect_delay_set(min_delay=1, max_delay=60)
        
        mailbox_id = options.get("WolsCA_MailboxID", "88889999")
        logging.info(f"Connecting to {broker} via Mailbox {mailbox_id}...")
        client.connect(broker, port, 60)

        start_heartbeat(client, mailbox_id) 
        
        client.loop_forever()
        
    except Exception as e:
        logging.error(f"FATAL ERROR during startup: {e}")
        logging.error(traceback.format_exc())
        sys.exit(1)

if __name__ == "__main__":
    main()