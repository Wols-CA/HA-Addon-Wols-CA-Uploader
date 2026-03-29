import logging

from secrets_handler import get_secret, update_secret
from public_key_handler import handle_public_key
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

    # 2. Secret Requests
    elif topic.startswith("wols-ca/secrets/request/"):
        secret_name = topic.split("/")[-1]
        secret = get_secret(secret_name)
        if secret:
            # TODO: Encrypt secret with public key before publishing!
            client.publish(f"wols-ca/secrets/response/{secret_name}", secret)
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
        else:
            logging.error(f"❌ HANDSHAKE REJECTED: Backend report: {payload}")
        return True

    # 5. Version Check
    elif topic == "wols-ca/uploader/required_version":
        required = payload.strip()
        if compare_versions(uploader_version, required):
            client.publish("wols-ca/uploader/status", "Uploader version too low, update required!", retain=True)
            logging.warning(f"Version too low: {uploader_version} (Required: {required})")
        else:
            client.publish("wols-ca/uploader/status", "Uploader version OK", retain=True)
            logging.info(f"Version OK: {uploader_version}")
        return True

    # No topic matched
    return False

def refresh_playlists():
    logging.info("Refreshing playlists...")

def compare_versions(current, required):
    return parse(current) < parse(required)