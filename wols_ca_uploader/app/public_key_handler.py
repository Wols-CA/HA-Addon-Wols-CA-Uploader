import base64
import logging
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from secrets_handler import get_secret

# Global key states
active_public_key = None  # The "Trusted" key
temp_public_key = None    # The "Probation" key

def handle_raw_bytes(client, msg):
    global temp_public_key
    try:
        logging.info("Handshake: Received raw byte-array. Reassembling...")
        
        # 1. Convert "80,85,66..." back into a real byte string
        payload_str = msg.payload.decode().strip()
        if "80,85,66,76,73,67" in payload_str:
            logging.info("Waiting for real key... ignoring placeholder.")
            return
        
        # Split by comma and convert each part to an integer
        byte_list = [int(b) for b in payload_str.split(',') if b.strip()]
        pem_data = bytes(byte_list)
        
        # 2. Load the key - this bypasses all Base64/Padding/Symbol errors
        new_key = serialization.load_pem_public_key(pem_data)
        
        if isinstance(new_key, rsa.RSAPublicKey):
            temp_public_key = new_key
            logging.info("🚀 RSA Key reassembled and loaded! Sending encrypted password...")
            
            # Now trigger the password send
            from mqtt_triggers import send_encrypted_payload
            from secrets_handler import get_secret
            
            mqtt_pw = get_secret("mqtt_password")
            send_encrypted_payload(client, "wols-ca/admin/encrypted_password", mqtt_pw)
        
    except Exception as e:
        logging.error(f"Failed to reassemble key: {e}")

def handle_public_key(client, msg):
    global temp_public_key, active_public_key

    try:
        logging.info("Reassembling public key from raw bytes...")
        
        # 1. Split the string by commas and convert back to integers
        # Example: "45,45,66" -> [45, 45, 66]
        payload_str = msg.payload.decode().strip()
        byte_list = [int(b) for b in payload_str.split(',') if b.strip()]
        
        # 2. Convert integer list directly to bytes
        pem_data = bytes(byte_list)
        
        # 3. Load the key - No more padding or symbol errors!
        new_key = serialization.load_pem_public_key(pem_data)
        
        if not isinstance(new_key, rsa.RSAPublicKey):
            raise TypeError("Invalid RSA Key Type")

        temp_public_key = new_key
        logging.info("🚀 RSA Key loaded perfectly via Byte-Array. Sending password...")

        from mqtt_triggers import send_encrypted_payload
        mqtt_pw = get_secret("mqtt_password")
        send_encrypted_payload(client, "wols-ca/admin/encrypted_password", mqtt_pw)

    except Exception as e:
        logging.error(f"Byte-Array Handshake Error: {e}")
        # ... keep your existing error/reset logic ...

def encrypted_text(topic, plaintext):
    """Encrypts text using the best available key; falls back to random noise."""
    key_to_use = active_public_key or temp_public_key

    if not key_to_use:
        logging.error(f"Encryption failed for {topic}: No keys available.")
        # Generate 256 bytes of random noise to mimic RSA-2048
        return base64.b64encode(secrets.token_bytes(256)).decode()

    # Perform RSA-OAEP encryption
    encrypted = key_to_use.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def is_public_key_active():
    """Corrected spelling to match mqtt_triggers.py usage."""
    if not active_public_key:
        return False
    return True

def promote_temp_key():
    """Moves the probation key to the trusted active state."""
    global active_public_key, temp_public_key
    if temp_public_key:
        active_public_key = temp_public_key
        logging.info("🚀 Handshake Verified: Key promoted to ACTIVE.")
    else:
        logging.error("Attempted to promote key, but temp_public_key is empty!")