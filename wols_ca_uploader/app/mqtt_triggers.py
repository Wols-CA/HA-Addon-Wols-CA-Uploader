import logging
from secrets_handler import get_secret
from public_key_handler import (
    handle_raw_bytes, 
    send_encrypted_payload,
    promote_temp_key, 
    is_public_key_active
)
import public_key_handler 
from packaging.version import parse

active_mqtt_user = None
active_mqtt_password = None

def load_mqtt_credentials():
    global active_mqtt_user, active_mqtt_password
    active_mqtt_user = get_setting("mqtt_username") 
    active_mqtt_password = get_setting("mqtt_password")
    if not active_mqtt_password:
        active_mqtt_password = get_secret("mqtt_password")
    else:
        logging.info("MQTT password not found in settings...")

def set_mqtt_credentials(user, password):
    global active_mqtt_user, active_mqtt_password
    active_mqtt_user = user
    active_mqtt_password = password

def get_MQTT_UserID():
    global active_mqtt_user
    if active_mqtt_user:
        return active_mqtt_user
    else:
        logging.warning("MQTT UserID requested but no active key. Returning None.")
        return None
    
def get_MQTT_Password():
    global active_mqtt_password
    if active_mqtt_password:
        return active_mqtt_password
    else:
        logging.warning("MQTT Password requested but no active key. Returning None.")
        return None

def handle_mqtt_message(client, msg, uploader_version):
    topic = msg.topic
    try:
        payload = msg.payload.decode().strip()
    except UnicodeDecodeError:
        logging.error("Failed to decode payload for topic %s", topic)
        return False

    # 1. Trigger Playlist Refresh
    if topic == "wols-ca/trigger/refresh_playlists":
        refresh_playlists()
        return True

    # 2. Secret Requests (Protected by Handshake)
    elif topic.startswith("wols-ca/secrets/request/"):
        secret_name = topic.split("/")[-1]
        
        if not is_public_key_active():
            logging.warning(f"Blocked request for {secret_name}: Handshake not active. Sending 'NO_ACTIVE_KEY'.")
            send_encrypted_payload(client, f"wols-ca/secrets/response/{secret_name}", "NO_ACTIVE_KEY")
            return True
            
        secret = get_secret(secret_name)
        if secret:
            send_encrypted_payload(client, f"wols-ca/secrets/response/{secret_name}", secret)
        else:
            logging.warning(f"Secret '{secret_name}' not found in secrets.yaml.")
        return True

    # 3. RSA Public Key Handshake (Consolidated)
    elif topic in ["wols-ca/keys/public", "wols-ca/keys/raw_bytes"]:
        # handle_raw_bytes now handles the CSV reassembly and sends the password
        handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password)
        return True

    # 4. Password Acknowledgment (Handshake Finalization)
    elif topic == "wols-ca/admin/password_ack":
        if payload == "OK":
            logging.info("🚀 HANDSHAKE SUCCESS: Backend verified the secret.")
            promote_temp_key()
        else:
            logging.error("❌ Handshake REJECTED: Backend did not accept the password.")
            # Reset keys to force a re-handshake
            public_key_handler.active_public_key = None
            public_key_handler.temp_public_key = None
        return True

    # 5. Version Check
    elif topic == "wols-ca/uploader/required_version":
        required = payload
        if compare_versions(uploader_version, required):
            logging.warning(f"Version too low: {uploader_version} (Required: {required})")
            # We don't overwrite the heartbeat here; just log the warning
        else:
            logging.info(f"Version check passed: {uploader_version}")
        return True

    # 6. Outbound / System topics to ignore
    elif topic in [
        "wols-ca/uploader/version", 
        "wols-ca/uploader/status", 
        "wols-ca/admin/request_key", 
        "wols-ca/admin/encrypted_password"
    ]:
        return True  

    # No topic matched
    return False

def refresh_playlists():
    """Placeholder for Spotify playlist logic."""
    logging.info("Refreshing Spotify playlists...")

def compare_versions(current, required):
    """Returns True if current version is less than required."""
    try:
        return parse(current) < parse(required)
    except Exception as e:
        logging.error(f"Version comparison error: {e}")
        return False