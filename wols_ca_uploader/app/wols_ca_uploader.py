import time
import logging
import os
import json
import random
import string
from mqtt_util import sanitize_mqtt_broker_url
from mqtt_int import MQTTInternalBridge
from mqtt_ext import MQTTExternalBridge
from mqtt_sub import MQTTProvisioningBridge
from secrets_handler import get_secret, update_secret

# ==============================================================================
# WOLS CA IT SECURITY NG - HUB ORCHESTRATOR
# ==============================================================================

logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt='%Y-%m-%dT%H:%M:%S'
)

def get_options():
    config_file = "/data/options.json"
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return {}

def ensure_service_instance_id(options):
    """Generates a unique Product-Key style ID for the service if left empty."""
    current_id = options.get("WolsCA_Service_InstanceID", "")
    if not current_id or current_id.strip() == "":
        parts = [''.join(random.choices(string.ascii_uppercase + string.digits, k=4)) for _ in range(3)]
        new_id = f"WOLS-HUB-{''.join(parts)}"
        logging.info(f"🆔 NEW SERVICE INSTANCE ID GENERATED: {new_id}")
        return new_id
    return current_id

def main():
    options = get_options()
    
    # We load the InstanceID from the config to use as the official Hub identity.
    # If the user fills in "WolsHub01", this will be used consistently across all bridges.
    uploader_id = ensure_service_instance_id(options)
    
    # We only store non-network secrets in secrets.yaml for the Web UI
    product_key = get_secret("wols_ca_product_key") or "wols-demo-key"

    # --- IDENTITY 1: INTERNAL (Safe Zone) ---
    int_ip, _ = sanitize_mqtt_broker_url(options.get("mqtt_int_broker", "core-mosquitto"), 1883)
    bridge_int = MQTTInternalBridge(
        client_id=f"WolsCA_Int_{uploader_id}",
        broker_ip=int_ip, 
        port=options.get("mqtt_int_port", 1883),
        user=options.get("mqtt_int_user"), 
        password=options.get("mqtt_int_password"),
        product_key=product_key
    )

    # --- IDENTITY 2: EXTERNAL (Uploader -> DMZ) ---
    ext_broker_raw = options.get("mqtt_ext_broker", "")
    if not ext_broker_raw:
        # Fallback to internal if external is not defined
        ext_ip, ext_port = int_ip, options.get("mqtt_int_port", 1883)
        ext_user, ext_pass = options.get("mqtt_int_user"), options.get("mqtt_int_password")
    else:
        ext_ip, _ = sanitize_mqtt_broker_url(ext_broker_raw, options.get("mqtt_ext_port", 1883))
        ext_port = options.get("mqtt_ext_port", 1883)
        ext_user = options.get("mqtt_ext_user")
        ext_pass = options.get("mqtt_ext_password")

    # --- IDENTITY 3: SERVICE (Passed down to the Spoke in Phase 5) ---
    ser_broker = options.get("mqtt_ser_broker") or ext_broker_raw or int_ip
    ser_port = options.get("mqtt_ser_port") or ext_port
    ser_user = options.get("mqtt_ser_user") or ext_user
    ser_pass = options.get("mqtt_ser_password") or ext_pass

    spoke_temp_config = {
        "broker": ser_broker, 
        "port": ser_port, 
        "user": ser_user, 
        "pass": ser_pass
    }

    # --- IDENTITY 4: PROVISIONING (OOB Bridge via Desktop Agent) ---
    sub_broker_raw = options.get("mqtt_sub_broker", "core-mosquitto")
    sub_ip, _ = sanitize_mqtt_broker_url(sub_broker_raw, options.get("mqtt_sub_port", 1883))
    
    bridge_sub = MQTTProvisioningBridge(
        client_id=f"WolsCA_Sub_{uploader_id}",
        broker_ip=sub_ip, 
        port=options.get("mqtt_sub_port", 1883),
        user=options.get("mqtt_sub_user"), 
        password=options.get("mqtt_sub_password"),
        temp_spoke_config=spoke_temp_config
    )

    # --- AIRGAP CALLBACK ---
    # Securely transfers decrypted, validated data from the DMZ to the Internal Broker
    def airgap_cb(p, t): 
        bridge_int.publish_seawater_data(p, t)

    bridge_ext = MQTTExternalBridge(
        client_id=f"WolsCA_Ext_{uploader_id}",
        broker_ip=ext_ip, 
        port=ext_port,
        user=ext_user, 
        password=ext_pass,
        product_key=product_key,
        data_callback=airgap_cb,
        uploader_version="1.0.0",
        service_id=uploader_id,  # Passes the Hub Name down for Header signatures
        ser_config=spoke_temp_config
    )

    logging.info(f"🚀 Starting Wols CA Hub Orchestrator. Hub Identity: {uploader_id}")
    
    # Start all isolated network bridges
    bridge_int.connect_and_start()
    bridge_ext.connect_and_start()
    bridge_sub.connect_and_start()

    # Keep the main thread alive
    while True: 
        time.sleep(5)

if __name__ == "__main__": 
    main()