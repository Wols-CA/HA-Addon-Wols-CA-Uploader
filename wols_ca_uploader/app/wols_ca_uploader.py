import time
import logging
from mqtt_util import sanitize_mqtt_broker_url
from mqtt_int import MQTTInternalBridge
from mqtt_ext import MQTTExternalBridge
from secrets_handler import get_secret

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

def main():
    product_key = get_secret("wols_ca_product_key") or "wols-demo-key"
    uploader_id = get_secret("wols_ca_uploader_id") or "upl-demo123"

    # 1. Haal configuraties op (In het echt uit options.json / secrets.yaml)
    ext_ip, ext_url = sanitize_mqtt_broker_url("emqx.external.cloud", 1883)
    int_ip, int_url = sanitize_mqtt_broker_url("core-mosquitto", 1883)
    
    # 2. Initialiseer de Interne Broker (De Veilige Haven)
    bridge_int = MQTTInternalBridge(
        client_id=f"WolsCA_Int_{uploader_id}",
        broker_ip=int_ip, port=1883,
        user="addons", password="int_password",
        product_key=product_key
    )

    # 3. Definieer de Airgap Callback (De brievenbus)
    def airgap_transfer_seawater(pos_num, temperature):
        """Deze functie is de ENIGE brug tussen Extern en Intern."""
        bridge_int.publish_seawater_data(pos_num, temperature)

    # 4. Initialiseer de Externe Broker (De Sluis), en geef de callback mee
    bridge_ext = MQTTExternalBridge(
        client_id=f"WolsCA_Ext_{uploader_id}",
        broker_ip=ext_ip, port=1883,
        user="wols_node", password="ext_password",
        product_key=product_key,
        data_callback=airgap_transfer_seawater
    )

    # 5. Start de motoren!
    logging.info("🚀 Starting Wols CA NG Security Bridge...")
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