import base64
import json
import logging
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Global key states - effectively the "Handshake Memory"
active_public_key = None  # The "Trusted" key (used for secrets)
temp_public_key = None    # The "Probation" key (waiting for password_ack)



def handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password):
    """
    Main entry point for RSA Public Key delivery.
    Loads the RSA object directly from the PEM string and sends the encrypted JSON credentials.
    """
    # FIX: We halen nu ook active_public_key binnen om deze te resetten
    global temp_public_key, active_public_key 
    topic = msg.topic
    
    try:
        logging.info(f"Handshake: Received key data from {topic}.")
        
        pem_data = msg.payload
        new_key = serialization.load_pem_public_key(pem_data)
        
        if isinstance(new_key, rsa.RSAPublicKey):
            # FIX: Omdat we een nieuwe sleutel krijgen, wissen we direct de oude actieve sleutel!
            active_public_key = None 
            
            temp_public_key = new_key
            logging.info("🚀 RSA Key loaded successfully! Initiating credential verification...")
            
            # 4. Package the credentials
            if active_mqtt_user and active_mqtt_password:
                credentials_payload = {
                    "user_id": active_mqtt_user,
                    "password": active_mqtt_password
                }
                json_string = json.dumps(credentials_payload)
                
                # 5. Encrypt and send
                logging.info("Sending encrypted JSON credentials to backend...")
                send_encrypted_payload(client, "wols-ca/admin/encrypted_credentials", json_string)
            else:
                logging.error("Active credentials are missing. Cannot send handshake response.")
        else:
            logging.error("Received key is not a valid RSA Public Key.")

    except Exception as e:
        logging.error(f"Failed to process key from {topic}: {e}")

def encrypted_text(topic, plaintext):
    """
    Encrypts text using the best available key.
    Prioritizes the Active (Trusted) key, falls back to Temp (Probation) key.
    """
    key_to_use = active_public_key or temp_public_key

    if not key_to_use:
        logging.error(f"Encryption failed for {topic}: No RSA keys available in memory.")
        # Return 256 bytes of random noise to mimic an RSA-2048 block (prevents crashing C++)
        return base64.b64encode(secrets.token_bytes(256)).decode()

    # Perform RSA-OAEP encryption (Standard for modern secure transport)
    encrypted = key_to_use.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def send_encrypted_payload(client, topic, plaintext):
    """
    Helper function to encrypt a string and publish it to an MQTT topic.
    """
    try:
        b64_string = encrypted_text(topic, plaintext)
        client.publish(topic, b64_string, qos=1)
        logging.debug(f"Published encrypted payload to {topic}")
    except Exception as e:
        logging.error(f"Failed to publish encrypted payload to {topic}: {e}")

def is_public_key_active():
    """Returns True if a handshake has been fully completed and verified."""
    return active_public_key is not None

def promote_temp_key():
    """Moves the probation key to the trusted active state upon password_ack=OK."""
    global active_public_key, temp_public_key
    if temp_public_key:
        active_public_key = temp_public_key
        # Optional: Clear temp key to ensure we don't reuse it
        # temp_public_key = None 
        logging.info("🚀 HANDSHAKE COMPLETE: RSA Key promoted to ACTIVE status.")
    else:
        logging.error("Promotion failed: No temporary key found in memory.")