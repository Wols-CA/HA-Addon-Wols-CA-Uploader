import json
import logging
import threading
from packaging.version import parse

# Local imports
from secrets_handler import get_secret, update_secret
from public_key_handler import (
    handle_raw_bytes, 
    send_encrypted_payload,
    promote_temp_key, 
    is_public_key_active
)
import public_key_handler 

# Global credentials memory
active_mqtt_user = None
active_mqtt_password = None

def set_mqtt_credentials(user, password):
    global active_mqtt_user, active_mqtt_password
    active_mqtt_user = user
    active_mqtt_password = password


class MQTTMessageRouter:
    """
    Routes incoming MQTT messages to their specific domain handlers.
    Spawns threads for long-running tasks to prevent blocking the MQTT network loop.
    """
    def __init__(self, uploader_version):
        self.uploader_version = uploader_version

    def route_message(self, client, msg):
        topic = msg.topic
        
        try:
            payload = msg.payload.decode().strip()
        except UnicodeDecodeError:
            logging.error(f"Failed to decode payload for topic {topic}")
            return False

        # 1. Routing: Handshake & Security Lifecycle
        if topic in ["wols-ca/keys/public", "wols-ca/keys/raw_bytes", "wols-ca/admin/password_ack"]:
            self._handle_handshake(client, topic, payload, msg)
            return True

        # 2. Routing: Secrets Management (Pickup from HA UI)
        elif "/Admin/Secrets/" in topic:
            self._handle_secrets_pickup(client, topic, payload)
            return True
            
        # 3. Routing: Secrets Requests (From C++)
        elif topic.startswith("wols-ca/secrets/request/"):
            self._handle_secret_request(client, topic)
            return True

        # 4. Routing: Heavy Triggers (Threaded)
        elif topic == "wols-ca/trigger/refresh_playlists":
            logging.info("Spawning background thread for playlist refresh...")
            threading.Thread(target=self._threaded_playlist_refresh, daemon=True).start()
            return True

        # 5. Routing: System & Version Control
        elif topic == "wols-ca/uploader/required_version":
            self._handle_version_check(payload)
            return True
            
        # Ignore known outbound topics
        elif topic in [
            "wols-ca/uploader/version", 
            "wols-ca/uploader/status", 
            "wols-ca/admin/request_key", 
            "wols-ca/admin/encrypted_credentials"
        ]:
            return True

        return False

    # ----------------------------------------------------------------
    # Domain-Specific Handlers
    # ----------------------------------------------------------------

    def _handle_handshake(self, client, topic, payload, msg):
        if topic in ["wols-ca/keys/public", "wols-ca/keys/raw_bytes"]:
            global active_mqtt_user, active_mqtt_password
            handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password)
            
        elif topic == "wols-ca/admin/password_ack":
            if payload == "OK":
                logging.info("🚀 HANDSHAKE SUCCESS: Backend verified the credentials.")
                promote_temp_key()
                
                # Elevate privileges: Subscribe to operational topics
                logging.info("🔓 Handshake verified. Subscribing to operational and secret topics...")
                client.subscribe([
                    ("wols-ca/trigger/#", 1),
                    ("spotify/+/Admin/Secrets/#", 1) 
                ])
            else:
                logging.error("❌ Handshake REJECTED: Backend did not accept the credentials.")
                public_key_handler.active_public_key = None
                public_key_handler.temp_public_key = None
                
                # Revoke privileges
                client.unsubscribe([
                    "wols-ca/trigger/#",
                    "spotify/+/Admin/Secrets/#"
                ])

    def _handle_secrets_pickup(self, client, topic, payload):
        # Ignore completely empty payloads
        if not payload:
            return 
            
        try:
            data = json.loads(payload)
            secret_value = data.get("current_value", "")
            
            # 1. Prevent loops: Ignore empty strings and our own masking text
            if not secret_value or secret_value == "Stored by Uploader":
                return
                
            # 2. Extract the secret name (e.g., "SpotifyClientSecret") from the topic
            secret_name = topic.split("/")[-1]
            
            # 3. Store the secret securely in secrets.yaml without asking questions
            if update_secret(secret_name, secret_value):
                logging.info(f"🔐 Secret '{secret_name}' picked up from MQTT and securely stored.")
                
                # 4. Mask the topic: Clear the plaintext password from the broker
                # and provide visual feedback in the HA dashboard.
                feedback = json.dumps({
                    "current_value": "Stored by Uploader",
                    "purpose": data.get("purpose", ""),
                    "remark": "Secret has been securely moved to internal storage."
                })
                client.publish(topic, feedback, qos=1, retain=True)
                
                # 5. Handle the special case for MQTT Password auto-healing
                if secret_name == "MQTTPassword":
                    global active_mqtt_password
                    active_mqtt_password = secret_value
                    logging.info("New MQTT Password loaded. Requesting new RSA key to trigger C++ connection test...")
                    client.publish("wols-ca/admin/request_key", "STARTUP_SYNC", qos=1)
                    
        except json.JSONDecodeError:
            logging.error(f"Malformed JSON payload on secret topic: {topic}")
    
    def _handle_secret_request(self, client, topic):
        secret_name = topic.split("/")[-1]
        
        if not is_public_key_active():
            logging.warning(f"Blocked request for {secret_name}: Handshake not active.")
            send_encrypted_payload(client, f"wols-ca/secrets/response/{secret_name}", "NO_ACTIVE_KEY")
            return
            
        secret = get_secret(secret_name)
        if secret:
            send_encrypted_payload(client, f"wols-ca/secrets/response/{secret_name}", secret)
        else:
            logging.warning(f"Secret '{secret_name}' not found.")

    def _handle_version_check(self, required):
        if self._compare_versions(self.uploader_version, required):
            logging.warning(f"Version too low: {self.uploader_version} (Required: {required})")
        else:
            logging.info(f"Version check passed: {self.uploader_version}")

    # ----------------------------------------------------------------
    # Threaded Tasks
    # ----------------------------------------------------------------

    def _threaded_playlist_refresh(self):
        """Runs in a separate thread to avoid blocking the MQTT loop."""
        try:
            logging.info("Starting Spotify playlist refresh...")
            # Execute your long-running Spotify logic here
            # refresh_playlists()
            logging.info("Spotify playlist refresh complete.")
        except Exception as e:
            logging.error(f"Error during threaded playlist refresh: {e}")

    # ----------------------------------------------------------------
    # Helpers
    # ----------------------------------------------------------------

    def _compare_versions(self, current, required):
        try:
            return parse(current) < parse(required)
        except Exception as e:
            logging.error(f"Version comparison error: {e}")
            return False


# --- Backward compatibility wrapper for wols_ca_uploader.py ---
# This allows you to keep your existing wols_ca_uploader.py code unchanged
_router_instance = None

def handle_mqtt_message(client, msg, uploader_version):
    global _router_instance
    if _router_instance is None:
        _router_instance = MQTTMessageRouter(uploader_version)
    return _router_instance.route_message(client, msg)

# ----------------------------------------------------------------
# Standalone Functions
# ----------------------------------------------------------------

def refresh_playlists():
    """Placeholder for Spotify playlist logic."""
    logging.info("Refreshing Spotify playlists...")
    # Add your actual heavy API calls or script logic here!

    # --- Backward compatibility wrapper for wols_ca_uploader.py ---
