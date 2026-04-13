import sys

if sys.version_info < (3, 12):
    print("FATAL: This addon requires Python 3.12 or higher.")
    sys.exit(1)

import threading
import time
import os
import json
import logging
import random
import string
import paho.mqtt.client as mqtt
import yaml

from mqtt_triggers import (
    handle_mqtt_message, 
    set_mqtt_credentials, 
    publish_dashboard_discovery, 
    MQTTMessageRouter,
    get_scrambled_path_helper
)
from secrets_handler import get_secret, update_secret
import wols_ca_web_ui

current_version = "Unknown"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def ensure_product_key():
    """Generates and securely stores the unique Wols CA Product Key if it does not exist."""
    key = get_secret("wols_ca_product_key")
    if not key:
        parts = [''.join(random.choices(string.ascii_lowercase + string.digits, k=4)) for _ in range(3)]
        key = f"wols-{'-'.join(parts)}"
        update_secret("wols_ca_product_key", key)
        logging.info(f"🔑 NEW WOLS CA PRODUCT KEY GENERATED: {key}")
    else:
        logging.info(f"🔑 Active Wols CA Product Key: {key}")
    return key

def start_heartbeat(client, product_key, interval=60):
    def heartbeat():
        while True:
            if client.is_connected():
                payload = json.dumps({"status": "online", "timestamp": int(time.time()), "version": current_version})
                topic = get_scrambled_path_helper(product_key, "uploader_status")
                client.publish(topic, payload, qos=0, retain=False)
            time.sleep(interval)
    threading.Thread(target=heartbeat, daemon=True).start()

def get_version_from_yaml():
    try:
        with open("/app/internal/version.yaml", "r") as f:
            return yaml.safe_load(f).get("version", "Unknown")
    except Exception: return "1.0.0"

def on_connect(client, userdata, flags, reason_code, properties=None):
    if reason_code == 0:
        logging.info("Connected to Wols CA MQTT Broker.")
        product_key = userdata.get('product_key')
        import hashlib
        mb_hash = hashlib.sha256(str(product_key).encode()).hexdigest()[:16]

        client.subscribe([
            ("wols_ca_mqtt/keys/public", 1),
            ("wols_ca_mqtt/admin/service_verify", 1), 
            ("wols_ca_mqtt/admin/password_ack", 1),
            ("wols_ca_mqtt/session/#", 1), 
            (f"wols_ca_mqtt/mb/{mb_hash}/+/set/#", 1)
        ])  
        
        client.publish("wols_ca_mqtt/admin/request_key", "STARTUP_SYNC", retain=False)
        publish_dashboard_discovery(client)
    else:
        logging.error(f"Connection failed with result code {reason_code}")

def sanitize_mqtt_broker_url(raw_broker, port):
    """
    Strips noise and enforces the Wols CA standard format: mqtt://<URL>:<port>
    """
    if "//" in str(raw_broker):
        clean_broker = str(raw_broker).split("//")[-1]
    else:
        clean_broker = str(raw_broker)
        
    clean_broker = clean_broker.split("/")[0]
    
    if ":" in clean_broker:
        clean_broker = clean_broker.split(":")[0]
        
    standard_url = f"mqtt://{clean_broker}:{port}"
    return clean_broker, standard_url

def main():
    global current_version
    try:
        current_version = get_version_from_yaml()
        config_file = "/data/options.json"
        options = {}
        if os.path.exists(config_file):
            with open(config_file, 'r') as f:
                options = json.load(f)

        raw_broker = options.get("mqtt_broker", "localhost")
        port = options.get("mqtt_port", 1883)
        user = options.get("mqtt_user")
        
        # --- WOLS CA FIX: Credential Scrubbing & Secure Vault Storage ---
        raw_password = options.get("mqtt_password", "")
        placeholder = "Safely stored by Wols CA Uploader"
        
        if raw_password and raw_password != placeholder:
            # A new plaintext password was detected in the configuration
            update_secret("mqtt_password", raw_password)
            
            # Scrub the password from the active configuration file
            options["mqtt_password"] = placeholder
            with open(config_file, 'w') as f:
                json.dump(options, f, indent=2)
                
            password = raw_password
            logging.info("🔒 Wols CA Security: MQTT Password moved to vault and scrubbed from UI config.")
        else:
            # The password is safe, retrieve it from the vault
            password = get_secret("mqtt_password") or ""
        # ----------------------------------------------------------------
        
        clean_broker_ip, wols_ca_standard_url = sanitize_mqtt_broker_url(raw_broker, port)
        set_mqtt_credentials(user, password, wols_ca_standard_url)
        product_key = ensure_product_key()
        
        import mqtt_triggers
        mqtt_triggers._router_instance = MQTTMessageRouter(current_version, product_key)

        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, userdata={'product_key': product_key, 'options': options})
        if user and password: client.username_pw_set(user, password)

        client.on_connect = on_connect
        client.on_message = lambda c, u, m: handle_mqtt_message(c, m, current_version)
        wols_ca_web_ui.set_interface_params(client)

        logging.info(f"Connecting to {clean_broker_ip} via Secure Dynamic Key...")
        
        client.connect(clean_broker_ip, port, 60)
        start_heartbeat(client, product_key) 
        
        threading.Thread(target=wols_ca_web_ui.start_web_server, daemon=True).start()
        logging.info("Wols CA Ingress Web UI started.")
        client.loop_forever()
    except Exception as e:
        logging.error(f"FATAL ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()