from secrets_handler import get_secret, update_secret
from public_key_handler import handle_public_key

def handle_mqtt_message(client, msg, uploader_version):
    topic = msg.topic
    payload = msg.payload.decode()
    if topic == "wols-ca/trigger/refresh_playlists":
        refresh_playlists()
        return True
    elif topic.startswith("wols-ca/secrets/request/"):
        secret_name = topic.split("/")[-1]
        secret = get_secret(secret_name)
        if secret:
            # TODO: Encrypt secret with public key before publishing!
            client.publish(f"wols-ca/secrets/response/{secret_name}", secret)
        return True
    elif topic == "wols-ca/keys/public":
        print("Received new public key for handshake")
        handle_public_key(client, msg)
        return True
    elif topic == "wols-ca/uploader/required_version":
        required = payload.strip()
        if compare_versions(uploader_version, required) < 0:
            client.publish("wols-ca/uploader/status", "Uploader version too low, update required!", retain=True)
        else:
            client.publish("wols-ca/uploader/status", "Uploader version OK", retain=True)
        return True
    # Add more triggers here
    return False

def refresh_playlists():
    print("Refreshing playlists...")

def compare_versions(current, required):
    from packaging import version
    return (version.parse(current) > version.parse(required)) - (version.parse(current) < version.parse(required))
