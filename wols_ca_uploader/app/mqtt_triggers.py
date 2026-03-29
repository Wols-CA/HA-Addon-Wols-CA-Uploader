import logging
from secrets_handler import get_secret, update_secret
from public_key_handler import (
    handle_public_key, 
    encrypted_text, 
    promote_temp_key, 
    is_public_key_active
)
import public_key_handler # For direct clearing of globals
from packaging.version import parse

def handle_mqtt_message(client, msg, uploader_version):
    topic = msg.topic
    try:
        payload = msg.payload.decode()
    except UnicodeDecodeError:
        logging.error("Failed to decode payload for topic %s", topic)
        return False

    # 1. Trigger Playlist Refresh
    if topic == "wols-ca/trigger/refresh_playlists":
        refresh_playlists()
        return True

    # 2. Secret Requests (Protected)
    elif topic.startswith("wols-ca/secrets/request/"):
        secret_name = topic.split("/")[-1]
        
        if not is_public_key_active():
            logging.warning(f"Blocked request for {secret_name}: No active handshake. Sending poison.")
            # Send poison pill automatically via helper
            send_encrypted_payload(client, f"wols-ca/secrets/response/{secret_name}", "NO_ACTIVE_KEY")
            return True
            
        secret = get_secret(secret_name)
        if secret:
            # FIX: Use the encryption helper instead of plain client.publish
            send_encrypted_payload(client, f"wols-ca/secrets/response/{secret_name}", secret)
        else:
            logging.warning(f"Secret '{secret_name}' not found.")
        return True

    # 3. Public Key Receipt (Handshake Step 1)
    elif topic == "wols-ca/keys/public":
        logging.info("Received new public key for handshake")
        handle_public_key(client, msg)
        return True

    # 4. Password Acknowledgment (Handshake Step 2)
    elif topic == "wols-ca/admin/password_ack":
        if payload == "OK":
            logging.info("🚀 HANDSHAKE SUCCESS: Backend verified the secret.")
            promote_temp_key()
        else:
            logging.error("❌ Handshake REJECTED by backend. Secrets remain locked.")
            public_key_handler.active_public_key = None
            public_key_handler.temp_public_key = None
        return True

    # 6. Version Check
    elif topic == "wols-ca/uploader/required_version":
        required = payload.strip()
        if compare_versions(uploader_version, required):
            client.publish("wols-ca/uploader/status", "Uploader version too low, update required!", retain=True)
            logging.warning(f"Version too low: {uploader_version} (Required: {required})")
        else:
            client.publish("wols-ca/uploader/status", "Uploader version OK", retain=True)
            logging.info(f"Version OK: {uploader_version}")
        return True
    elif topic in ["wols-ca/uploader/version", "wols-ca/admin/request_key", "wols-ca/admin/encrypted_password"]:
        return True  # Ignore our own outbound traffic
    # No topic matched
    return False

def send_encrypted_payload(client, topic, plaintext):
    """Encrypts text and publishes it to MQTT. Handles poison pills if keys are missing."""
    b64_string = encrypted_text(topic, plaintext)
    client.publish(topic, b64_string)
    logging.debug(f"Published encrypted payload to {topic}")

def refresh_playlists():
    logging.info("Refreshing playlists...")

def compare_versions(current, required):
    return parse(current) < parse(required)