import json
import hashlib
from mqtt_util import MQTTBaseClient
import public_key_handler
import secrets_handler

class MQTTExternalBridge(MQTTBaseClient):
    def __init__(self, client_id, broker_ip, port, user, password, product_key, data_callback):
        super().__init__(client_id, broker_ip, port, user, password)
        self.product_key = product_key
        self.ext_password = password
        self.data_callback = data_callback # De 'brievenbus' naar het interne netwerk

    def on_successful_connect(self):
        self.logger.info("🌐 EXTERNAL: Zero-Trust Zone ready. Subscribing to public channels...")
        import hashlib
        mb_hash = hashlib.sha256(str(self.product_key).encode()).hexdigest()[:16]
        
        # Abonneer op de publieke paden en sessie paden
        self.client.subscribe([
            ("wols_ca_mqtt/keys/public", 1),
            ("wols_ca_mqtt/admin/service_verify", 1),
            ("wols_ca_mqtt/session/#", 1)
        ])
        self.publish("wols_ca_mqtt/admin/request_key", "STARTUP_SYNC", retain=False)

    def on_message(self, client, userdata, msg):
        topic = msg.topic.lower()
        
        # --- VERWERK BINNENKOMENDE SEAWATER DATA ---
        if "/seawaterdetails/state/position" in topic:
            self._process_encrypted_seawater(msg.payload.decode().strip())
        
        # [Hier komt ook de rest van de public_key_handler logica voor Step A/B/C]

    def _process_encrypted_seawater(self, b64_payload):
        """1. Ontcijfer 2. Verifieer 3. Stuur door via Callback"""
        try:
            decrypted_str = public_key_handler.decrypt_from_service(b64_payload)
            if not decrypted_str: return

            envelope = json.loads(decrypted_str)
            raw_payload = envelope.get("payload", "")
            signature = envelope.get("signature", "")

            # Integriteitscontrole
            expected_sig = hashlib.sha256((raw_payload + (self.ext_password or "")).encode()).hexdigest()
            if signature != expected_sig:
                self.logger.error("🚨 SECURITY: Invalid signature on SeaWater data! Dropping.")
                return

            data = json.loads(raw_payload)
            sensor_id = data.get("id") # Bijv. "Position1"
            pos_num = sensor_id.replace("Position", "") 
            temperature = data.get("temperature")

            # Bewaar de onbewerkte string veilig voor de Web UI
            secrets_handler.update_secret(f"State_{sensor_id}", raw_payload)
            
            # Sluis de schone data door naar de veilige haven via de callback!
            self.data_callback(pos_num, temperature)
            self.logger.info(f"🌐 EXTERNAL: Data verified for Position {pos_num}. Sent to Airgap.")

        except Exception as e:
            self.logger.error(f"Error processing encrypted data: {e}")