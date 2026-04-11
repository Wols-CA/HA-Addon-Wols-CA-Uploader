import json
import logging
import os
import time
import hashlib

# Local imports
import secrets_handler
import public_key_handler

active_mqtt_user = None
active_mqtt_password = None
last_sent_config = {}

def set_mqtt_credentials(user, password):
    global active_mqtt_user, active_mqtt_password
    active_mqtt_user = user
    active_mqtt_password = password

def publish_dashboard_discovery(client):
    """Herstelt de ontbrekende discovery functie voor Home Assistant."""
    device_info = {
        "identifiers": ["wols_ca_vault"],
        "name": "wols_ca Configuration Vault",
        "manufacturer": "Wols CA"
    }

    buttons = {
        "SpotifyReload": ("wols_ca_mqtt/admin/command/SpotifyReload", "mdi:reload"),
        "SpotifyReset": ("wols_ca_mqtt/admin/command/SpotifyReset", "mdi:delete-alert"),
        "SeaWaterReload": ("wols_ca_mqtt/admin/command/SeaWaterReload", "mdi:reload"),
        "SeaWaterReset": ("wols_ca_mqtt/admin/command/SeaWaterReset", "mdi:delete-alert")
    }
    
    for btn_name, (cmd_topic, icon) in buttons.items():
        payload = {
            "name": btn_name,
            "unique_id": f"wols_ca_btn_{btn_name}",
            "icon": icon,
            "command_topic": cmd_topic,
            "payload_press": "PRESS",
            "device": device_info
        }
        client.publish(f"homeassistant/button/wols_ca/{btn_name}/config", json.dumps(payload), retain=True)

class MQTTMessageRouter:
    def __init__(self, uploader_version):
        self.uploader_version = uploader_version
        self.logger = logging.getLogger(__name__)
        self._cached_options = {}
        self._options_last_read = 0
        self._options_cache_ttl = 300 
        self.topic_map = {}

    def _get_options(self):
        current_time = time.time()
        if current_time - self._options_last_read > self._options_cache_ttl:
            options_file = "/data/options.json"
            if os.path.exists(options_file):
                try:
                    with open(options_file, "r") as f:
                        self._cached_options = json.load(f)
                    self._options_last_read = current_time
                except Exception as e:
                    self.logger.error(f"Error reading options.json: {e}")
            else:
                self._cached_options = {}
        return self._cached_options

    def _get_scrambled_path(self, sub_topic):
        options = self._get_options()
        mailbox_id = options.get("WolsCA_MailboxID", "88889999")
        mb_hash = hashlib.sha256(mailbox_id.encode()).hexdigest()[:16]
        sub_hash = hashlib.sha256(sub_topic.encode()).hexdigest()[:16]
        return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}"

    def route_message(self, client, msg):
        topic = msg.topic
        try:
            if not msg.payload:
                return False
            payload_str = msg.payload.decode().strip()
            data = json.loads(payload_str) if payload_str.startswith('{') else None
        except Exception:
            payload_str = msg.payload.decode().strip() if msg.payload else ""
            data = None

        structure_hash = hashlib.sha256("topic_structure".encode()).hexdigest()[:16]
        if topic.endswith(structure_hash):
            if data and data.get("instance_name") == "ha_service_uploader":
                self.topic_map = {m['id']: m['topic'] for m in data['modules']}
                self.logger.info("🚀 Successfully loaded secure structure")
                return True

        if topic in ["wols_ca_mqtt/keys/public", 
                     "wols_ca_mqtt/admin/password_ack", 
                     "wols_ca_mqtt/keys/public"]:
            self._handle_handshake(client, topic, payload_str, msg)
            return True

        return False

    def _handle_handshake(self, client, topic, payload, msg):
        if "keys/public" in topic:
            public_key_handler.handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password)
        elif "password_ack" in topic:
            if payload == "ACK":
                self.logger.info("🚀 SECURE HANDSHAKE SUCCESS")
                public_key_handler.promote_temp_key()
                inbox = self._get_scrambled_path("inbox")
                client.subscribe(inbox, 1)
                self._send_ha_service_settings(client)
                self._send_spotify_details(client)
                self._send_seawater_details(client)

    def _send_config_response(self, client, key, data):
        options = self._get_options()
        uploader_name = options.get("WolsCA_UploaderName", "ha_uploader_main")
        service_id = options.get("WolsCA_ServiceID", "unknown_service")

        envelope = {
            "header": {
                "from": uploader_name,
                "to": service_id.lower().replace(" ", "_"),
                "timestamp": int(time.time()),
                "msg_type": "config_update",
                "encrypted": public_key_handler.is_public_key_active()
            },
            "payload": data
        }

        topic = self._get_scrambled_path(key)
        client.publish(topic, json.dumps(envelope), retain=False)

    def _send_ha_service_settings(self, client):
        options = self._get_options()
        data = {
            "BrokerURL": options.get("mqtt_broker", ""),
            "MqttUser": active_mqtt_user,
            "MqttPassword": active_mqtt_password,
            "ConsoleToMqtt": options.get("ConsoleToMqtt", False),
            "LogModus": options.get("LogModus", "INFO"),
            "RefreshMinutes": options.get("RefreshMinutes", 45),
            "MailboxID": options.get("WolsCA_MailboxID", "88889999")
        }
        self._send_config_response(client, "HAServiceSettings", data)

    def _send_spotify_details(self, client, force_empty=False):
        options = self._get_options()
        enabled = options.get("SpotifyEnabled", False)
        if not enabled or force_empty:
            self._send_config_response(client, "SpotifyDetails", {"Enabled": False})
            return

        playlist_sets = []
        max_sets = int(options.get("PlaylistSets", 0))
        for i in range(1, max_sets + 1):
            source = secrets_handler.get_secret(f"SourceID{i}")
            target = secrets_handler.get_secret(f"TargetID{i}")
            if source and target:
                playlist_sets.append({
                    "source": source, "target": target,
                    "play_time": secrets_handler.get_secret(f"PlayTime{i}")
                })

        data = {
            "Enabled": True,
            "Automate": options.get("SpotifyAutomate", False),
            "ClientID": secrets_handler.get_secret("SpotifyClientID"),
            "ClientSecret": secrets_handler.get_secret("ClientIDSecret"),
            "Sets": playlist_sets
        }
        self._send_config_response(client, "SpotifyDetails", data)

    def _send_seawater_details(self, client, force_empty=False):
        options = self._get_options()
        enabled = options.get("SeaWaterEnabled", False)
        if not enabled or force_empty:
            self._send_config_response(client, "SeaWaterDetails", {"Enabled": False})
            return

        positions = []
        max_pos = int(options.get("SeaWaterNumber", 0))
        for i in range(1, max_pos + 1):
            pos = secrets_handler.get_secret(f"Position{i}")
            if pos: positions.append(pos)

        data = {
            "Enabled": True,
            "SensorInterval": int(options.get("SensorInterval", 30)),
            "Positions": positions
        }
        self._send_config_response(client, "SeaWaterDetails", data)

def handle_mqtt_message(client, msg, uploader_version):
    """Verwerkt inkomende MQTT berichten via de router instantie."""
    global _router_instance
    if _router_instance is None:
        _router_instance = MQTTMessageRouter(uploader_version)
    return _router_instance.route_message(client, msg)

# Initialiseer de globale instantie op None
_router_instance = None