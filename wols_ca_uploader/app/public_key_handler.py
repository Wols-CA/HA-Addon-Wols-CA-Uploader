import base64
import logging
import secrets
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from secrets_handler import get_secret

# Global key states
active_public_key = None  # The "Trusted" key
temp_public_key = None    # The "Probation" key

def handle_public_key(client, msg):
    global temp_public_key, active_public_key
    try:
        logging.info("Handling received public key for handshake...")

        from mqtt_triggers import send_encrypted_payload

        # Reset states on a new key attempt
        active_public_key = None
        temp_public_key = None

        # 1.a Log the RAW payload to see exactly what arrived
        # Ensure we use the same variable name throughout
        payload = msg.payload.decode().strip().replace('"', '') 

        # 1.b Convert URL-safe Base64 to Standard Base64
        # This fixes the 'InvalidByte(6, 95)' underscore error
        payload = payload.replace('-', '+').replace('_', '/')

        # 1.c FIX: Add missing Base64 padding
        # This resolves the 'InvalidPadding' error
        missing_padding = len(payload) % 4
        if missing_padding:
            payload += '=' * (4 - missing_padding)
        
        logging.debug(f"DEBUG: Raw Key Received: |{payload}|")

        # 2. Check and add PEM headers if missing
        header = "-----BEGIN PUBLIC KEY-----"
        footer = "-----END PUBLIC KEY-----"
        
        if header not in payload:
            logging.info("PEM headers missing. Adding them automatically.")
            # Ensure the base64 body is clean of any stray internal headers
            clean_body = payload.replace(header, "").replace(footer, "").strip()
            # Reconstruct the full PEM format
            payload = f"{header}\n{clean_body}\n{footer}"     
        
        # 3. Attempt to load the reconstructed key
        new_key = serialization.load_pem_public_key(payload.encode())
        
        if not isinstance(new_key, rsa.RSAPublicKey):
            raise TypeError("Invalid RSA Key Type")
            
        temp_public_key = new_key
        logging.info("Phase 1: New key placed in probation. Sending password for verification...")
        
        # Local import to avoid circular dependency
        mqtt_pw = get_secret("mqtt_password")
        
        # Encrypt with the temp_public_key via the helper
        send_encrypted_payload(client, "wols-ca/admin/encrypted_password", mqtt_pw)
        
    except Exception as e:
        logging.error(f"Handshake Error: {e}. Clearing keys and forcing reset.")
        temp_public_key = None
        active_public_key = None
        
        # Trigger the "Poison Pill" via the encryption helper
        send_encrypted_payload(client, "wols-ca/admin/encrypted_password", "FORCE_RESET")

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