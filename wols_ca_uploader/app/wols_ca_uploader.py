import time
import logging
import os
import json
from mqtt_util import sanitize_mqtt_broker_url
from mqtt_int import MQTTInternalBridge
from mqtt_ext import MQTTExternalBridge
from secrets_handler import get_secret, update_secret

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
    config_file = "/data/options.json"
    options_changed = False
    placeholder = "Safely stored by Wols CA Uploader"
    
    # --- WOLS CA VAULT SYNC: HA Configuratie is Leidend ---
    logging.info("🔄 Synchronizing HA Configuration with Wols CA Secure Vault...")
    
    for key, value in options.items():
        # Uitzondering voor wachtwoorden
        if "password" in key.lower():
            if value and value != placeholder:
                # Gebruiker heeft een nieuw wachtwoord ingevoerd -> Overschrijf Kluis
                update_secret(key, value)
                options[key] = placeholder
                options_changed = True
                logging.info(f"🔒 Security: New password detected for '{key}', scrubbed from UI.")
        else:
            # Generieke instellingen (IP's, SeaWaterNumber, PlaylistSets, etc.)
            # UI heeft prioriteit. Bij verschil: update de kluis.
            current_secret = get_secret(key)
            if current_secret != value:
                update_secret(key, value)
                
    # Sla de opgeschoonde UI configuratie (met placeholders) direct op
    if options_changed:
        with open(config_file, 'w') as f:
            json.dump(options, f, indent=2)

    # --- INITIALISATIE VARIABELEN ---
    product_key = get_secret("wols_ca_product_key") or "wols-demo-key"
    uploader_id = get_secret("wols_ca_uploader_id") or "upl-demo123"

    int_broker_raw = options.get("mqtt_int_broker", "core-mosquitto")
    int_port = options.get("mqtt_int_port", 1883)
    int_user = options.get("mqtt_int_user", "addons")
    int_pass = get_secret("mqtt_int_password") or ""

    ext_broker_raw = options.get("mqtt_ext_broker", "")
    ext_port = options.get("mqtt_ext_port", 1883)
    ext_user = options.get("mqtt_ext_user", "")
    ext_pass = get_secret("mqtt_ext_password") or ""

    # --- WOLS CA FIX: Single-Broker Test Mode ---
    if not ext_broker_raw or ext_broker_raw.strip() == "":
        logging.warning("⚠️ No External Broker configured. Falling back to Internal Broker for testing (Single-Broker Mode).")
        ext_broker_raw = int_broker_raw
        ext_port = int_port
        ext_user = int_user
        ext_pass = int_pass # Gebruik het veilige, uitgepakte interne wachtwoord!

    # Schoon de URL's op
    ext_ip, ext_url = sanitize_mqtt_broker_url(ext_broker_raw, ext_port)
    int_ip, int_url = sanitize_mqtt_broker_url(int_broker_raw, int_port)
    
    # Initialiseer de Interne Broker (De Veilige Haven)
    bridge_int = MQTTInternalBridge(
        client_id=f"WolsCA_Int_{uploader_id}",
        broker_ip=int_ip, port=int_port,
        user=int_user, password=int_pass,
        product_key=product_key
    )

    # Definieer de Airgap Callback (De brievenbus)
    def airgap_transfer_seawater(pos_num, temperature):
        bridge_int.publish_seawater_data(pos_num, temperature)

    # Initialiseer de Externe Broker (De Sluis)
    bridge_ext = MQTTExternalBridge(
        client_id=f"WolsCA_Ext_{uploader_id}",
        broker_ip=ext_ip, port=ext_port,
        user=ext_user, password=ext_pass,
        product_key=product_key,
        data_callback=airgap_transfer_seawater
    )

    # Start de motoren!
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