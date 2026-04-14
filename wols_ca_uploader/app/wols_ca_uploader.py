import time
import logging
import os
import json
from mqtt_util import sanitize_mqtt_broker_url
from mqtt_int import MQTTInternalBridge
from mqtt_ext import MQTTExternalBridge
from secrets_handler import get_secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def get_options():
    """Leest de configuratie uit de Home Assistant add-on"""
    config_file = "/data/options.json"
    if os.path.exists(config_file):
        with open(config_file, 'r') as f:
            return json.load(f)
    return {}

def main():
    options = get_options()
    
    product_key = get_secret("wols_ca_product_key") or "wols-demo-key"
    uploader_id = get_secret("wols_ca_uploader_id") or "upl-demo123"

    # 1. Haal de Interne Broker (Home Assistant) configuratie op
    int_broker_raw = options.get("mqtt_int_broker", "core-mosquitto")
    int_port = options.get("mqtt_int_port", 1883)
    int_user = options.get("mqtt_int_user", "addons")
    int_pass = options.get("mqtt_int_password", "")

    # 2. Haal de Externe Broker configuratie op
    ext_broker_raw = options.get("mqtt_ext_broker", "")
    ext_port = options.get("mqtt_ext_port", 1883)
    ext_user = options.get("mqtt_ext_user", "")
    ext_pass = options.get("mqtt_ext_password", "")

    # --- WOLS CA FIX: Single-Broker Test Mode ---
    # Als er geen externe broker is gedefinieerd, val terug op de interne broker.
    # Dit voorkomt crashes tijdens het testen, terwijl de DMZ-architectuur in de code behouden blijft.
    if not ext_broker_raw or ext_broker_raw.strip() == "":
        logging.warning("⚠️ No External Broker configured. Falling back to Internal Broker for testing (Single-Broker Mode).")
        ext_broker_raw = int_broker_raw
        ext_port = int_port
        ext_user = int_user
        ext_pass = int_pass

    # Schoon de URL's op
    ext_ip, ext_url = sanitize_mqtt_broker_url(ext_broker_raw, ext_port)
    int_ip, int_url = sanitize_mqtt_broker_url(int_broker_raw, int_port)
    
    # 3. Initialiseer de Interne Broker (De Veilige Haven)
    bridge_int = MQTTInternalBridge(
        client_id=f"WolsCA_Int_{uploader_id}",
        broker_ip=int_ip, port=int_port,
        user=int_user, password=int_pass,
        product_key=product_key
    )

    # 4. Definieer de Airgap Callback (De brievenbus)
    def airgap_transfer_seawater(pos_num, temperature):
        """Deze functie is de ENIGE brug tussen Extern en Intern."""
        bridge_int.publish_seawater_data(pos_num, temperature)

    # 5. Initialiseer de Externe Broker (De Sluis), en geef de callback mee
    bridge_ext = MQTTExternalBridge(
        client_id=f"WolsCA_Ext_{uploader_id}",
        broker_ip=ext_ip, port=ext_port,
        user=ext_user, password=ext_pass,
        product_key=product_key,
        data_callback=airgap_transfer_seawater
    )

    # 6. Start de motoren!
    logging.info(f"🚀 Starting Wols CA NG Security Bridge (ID: {uploader_id})...")
    bridge_int.connect_and_start()
    bridge_ext.connect_and_start()

    # Houd het hoofdscript levend
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Shutting down...")

if __name__ == "__main__":
    main()