import json
import logging
import base64
import random
import string
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from mqtt_util import MQTTBaseClient

class MQTTProvisioningBridge(MQTTBaseClient):
    """
    Handles Phase 3 of the Wols CA Zero-Trust Onboarding.
    Listens for the Desktop Agent, generates the MS-Key, and encrypts 
    the identity securely for the specific Spoke Hardware.
    """
    def __init__(self, client_id, broker_ip, port, user, password, temp_spoke_config):
        super().__init__(client_id, broker_ip, port, user, password)
        self.temp_spoke_config = temp_spoke_config
        self.bridge_name = "PROVISIONING (OOB Zone)"

    def on_successful_connect(self):
        self.logger.info(f"🛠️ {self.bridge_name}: Listening for Wols CA Desktop Agents...")
        self.client.subscribe("wols_ca_mqtt/admin/provision/request", qos=1)

    def on_message(self, client, userdata, msg):
        if msg.topic == "wols_ca_mqtt/admin/provision/request":
            self._handle_provision_request(msg.payload.decode('utf-8'))

    def _handle_provision_request(self, payload_str):
        try:
            dna_data = json.loads(payload_str)
            cpu_id = dna_data.get("hardware_dna", {}).get("cpu_id", "UNKNOWN")
            spoke_pub_pem = dna_data.get("cryptography", {}).get("public_key", "")

            if not spoke_pub_pem:
                self.logger.error("❌ No Public Key found in DNA Payload.")
                return

            self.logger.info(f"📥 Received DNA for CPU: {cpu_id}. Generating identity...")

            # 1. Load the Spoke's Public Key into memory
            # Note: We replace escaped newlines just in case the JSON stringified them
            clean_pem = spoke_pub_pem.replace('\\n', '\n').replace('\\r', '')
            spoke_pub_key = serialization.load_pem_public_key(clean_pem.encode('utf-8'))

            # 2. Generate the definitive MS-Key (Hardware Passport ID)
            ms_key = f"WOLS-{self._generate_random_string(4)}-{self._generate_random_string(4)}-{self._generate_random_string(4)}"

            # 3. Construct the highly sensitive Onboard Package
            onboard_pkg = {
                "ms_key": ms_key,
                "temp_mqtt_url": self.temp_spoke_config.get("broker"),
                "temp_mqtt_port": self.temp_spoke_config.get("port"),
                "temp_mqtt_user": self.temp_spoke_config.get("user"),
                "temp_mqtt_pass": self.temp_spoke_config.get("pass")
            }

            # 4. Encrypt the package using the Spoke's Public Key
            plaintext_bytes = json.dumps(onboard_pkg).encode('utf-8')
            
            # Using strict OAEP padding for enterprise security
            encrypted_bytes = spoke_pub_key.encrypt(
                plaintext_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()), 
                    algorithm=hashes.SHA256(), 
                    label=None
                )
            )
            b64_encrypted = base64.b64encode(encrypted_bytes).decode('utf-8')

            # 5. Burn 1: The plaintext identity only existed in RAM during this function.
            # We now construct the safe, encrypted response for the Desktop Agent.
            response_payload = json.dumps({
                "cpu_id": cpu_id, # Echo the CPU ID so the Desktop Agent knows it matches
                "encrypted_identity": b64_encrypted
            })

            self.publish("wols_ca_mqtt/admin/provision/response", response_payload, retain=False)
            self.logger.info(f"✅ Secure Identity '{ms_key}' generated and encrypted for {cpu_id}.")

        except Exception as e:
            self.logger.error(f"Error handling provision request: {e}")

    def _generate_random_string(self, length):
        return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))