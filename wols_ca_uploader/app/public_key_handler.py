import base64
import logging
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from secrets_handler import get_secret

# Global key states - effectively the "Handshake Memory"
active_public_key = None  # The "Trusted" key (used for secrets)
temp_public_key = None    # The "Probation" key (waiting for password_ack)

def handle_raw_bytes(client, msg):
    """
    Main entry point for RSA Public Key delivery.
    Reassembles the byte-array, loads the RSA object, and sends the encrypted password.
    """
    global temp_public_key
    topic = msg.topic
    
    try:
        logging.info(f"Handshake: Received key data from {topic}. Reassembling...")
        
        # 1. Decode and check for placeholders
        payload_str = msg.payload.decode().strip()
        
        # Guard: Ignore the 'PUBLIC_KEY_PLACEHOLDER' string (ASCII 80,85,66...)
        if "80,85,66,76,73,67" in payload_str:
            logging.info("Service is still initializing... ignoring placeholder key.")
            return
        
        # 2. Convert CSV string "45,45,66..." back into a real byte string
        try:
            byte_list = [int(b) for b in payload_str.split(',') if b.strip()]
            pem_data = bytes(byte_list)
        except ValueError as ve:
            logging.error(f"Malformed byte-array string: {ve}")
            return

        # 3. Load the RSA Key directly from PEM bytes
        # This bypasses all Base64/Symbol encoding issues
        new_key = serialization.load_pem_public_key(pem_data)
        
        if isinstance(new_key, rsa.RSAPublicKey):
            temp_public_key = new_key
            logging.info("🚀 RSA Key loaded successfully! Initiating password verification...")
            
            # 4. Fetch the MQTT password from secrets.yaml
            mqtt_pw = get_secret("mqtt_password")
            
            if mqtt_pw:
                # 5. Encrypt password with the NEW key and send to C++ backend
                send_encrypted_payload(client, "wols-ca/admin/encrypted_password", mqtt_pw)
            else:
                logging.error("Could not find 'mqtt_password' in secrets.yaml. Handshake stalled.")
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