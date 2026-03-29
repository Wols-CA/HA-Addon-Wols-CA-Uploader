import base64
import logging
import secrets  # For random password generation
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from secrets_handler import get_secret

def handle_public_key(client, msg):
    try:
        public_key_pem = msg.payload.decode().strip()
        
        # 1. Load and validate the key
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise TypeError("Received key is not an RSA Public Key")

        # 2. Get the real secret or generate a random "answer" as fallback
        mqtt_password = get_secret("mqtt_password")
        if not mqtt_password:
            logging.warning("Real MQTT password not found. Sending random fallback.")
            mqtt_password = secrets.token_urlsafe(16)  # Random 16-char string

        # 3. Encrypt using RSA-OAEP
        encrypted = public_key.encrypt(
            mqtt_password.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        encrypted_b64 = base64.b64encode(encrypted).decode()

        # 4. Publish to the specific backend topic
        # Note: Match the topic your C++ backend expects!
        client.publish("wols-ca/admin/encrypted_password", encrypted_b64)
        logging.info("Encrypted password sent to backend. Waiting for ACK...")

    except Exception as e:
        logging.error(f"Handshake Failed - Public Key Error: {e}")