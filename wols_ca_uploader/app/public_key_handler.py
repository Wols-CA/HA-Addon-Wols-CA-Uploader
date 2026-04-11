import json
import logging
import os
import time
import hashlib

import secrets_handler
import public_key_handler

active_mqtt_user = None
active_mqtt_password = None
_router_instance = None

def set_mqtt_credentials(user, password):
    global active_mqtt_user, active_mqtt_password
    active_mqtt_user = user
    active_mqtt_password = password

def get_scrambled_path_helper(mailbox_id, sub_topic):
    """Berekent het troebele pad conform de Wols CA standaard."""
    mb_hash = hashlib.sha256(mailbox_id.encode()).hexdigest()[:16]
    sub_hash = hashlib.sha256(sub_topic.encode()).hexdigest()[:16]
    return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}"

def publish_dashboard_discovery(client):
    """Genereert 172 discovery velden voor HA."""
    options = {}
    if _router_instance:
        options = _router_instance._get_options()
    
    mailbox_id = options.get("WolsCA_MailboxID", "88889999")
    
    dev_seawater = {"identifiers": [f"wols_ca_{mailbox_id}_sw"], "name": "Wols CA SeaWater System", "manufacturer": "Wols CA"}
    dev_spotify = {"identifiers": [f"wols_ca_{mailbox_id}_sp"], "name": "Wols CA Spotify System", "manufacturer": "Wols CA"}

    sw_mailbox = get_scrambled_path_helper(mailbox_id, "SeaWaterDetails")
    for i in range(1, 101):
        sw_payload = {
            "name": f"SW Position {i}",
            "unique_id": f"wols_ca_{mailbox_id}_sw_pos_{i}",
            "icon": "mdi:map-marker-distance",
            "command_topic": f"{sw_mailbox}/set/Position{i}",
            "state_topic": f"{sw_mailbox}/state/Position{i}",
            "device": dev_seawater
        }
        client.publish(f"homeassistant/text/wols_ca/sw_pos_{i}/config", json.dumps(sw_payload), retain=True)

    spot_mailbox = get_scrambled_path_helper(mailbox_id, "SpotifyDetails")
    for i in range(1, 25):
        for field in ["SourceID", "TargetID", "PlayTime"]:
            spot_payload = {
                "name": f"Spotify {field} {i}",
                "unique_id": f"wols_ca_{mailbox_id}_spot_{field.lower()}_{i}",
                "icon": "mdi:music-box-outline",
                "command_topic": f"{spot_mailbox}/set/{field}{i}",
                "state_topic": f"{spot_mailbox}/state/{field}{i}",
                "device": dev_spotify
            }
            client.publish(f"homeassistant/text/wols_ca/spot_{field.lower()}_{i}/config", json.dumps(spot_payload), retain=True)

    logging.info("🚀 Dashboard Discovery: 172 secure entities registered.")

class MQTTMessageRouter:
    def __init__(self, uploader_version):
        self.uploader_version = uploader_version
        self.logger = logging.getLogger(__name__)
        self._cached_options = {}
        self._options_last_read = 0

    def _get_options(self):
        if time.time() - self._options_last_read > 300:
            if os.path.exists("/data/options.json"):
                try:
                    with open("/data/options.json", "r") as f:
                        self._cached_options = json.load(f)
                    self._options_last_read = time.time()
                except Exception:
                    pass
        return self._cached_options

    def route_message(self, client, msg):
        topic = msg.topic
        try:
            if not msg.payload:
                return False
            payload_str = msg.payload.decode().strip()
        except Exception:
            return False

        # 1. Handshake
        if topic in ["wols_ca_mqtt/keys/public", "wols_ca_mqtt/admin/password_ack"]:
            self._handle_handshake(client, topic, payload_str, msg)
            return True

        # 2. Inkomende Commando's (set) vanuit Home Assistant UI
        if "/set/" in topic:
            field_name = topic.split("/")[-1]
            if secrets_handler.update_secret(field_name, payload_str):
                self.logger.info(f"📍 Securely stored {field_name}")
                
                # Update HA Status
                state_topic = topic.replace("/set/", "/state/")
                client.publish(state_topic, payload_str, retain=True)

                # Push naar Service
                if "Position" in field_name:
                    self._send_seawater_details(client)
                else:
                    self._send_spotify_details(client)
            return True

        return False

    def _handle_handshake(self, client, topic, payload, msg):
        if "keys/public" in topic:
            public_key_handler.handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password)
        elif "password_ack" in topic:
            if payload == "ACK":
                self.logger.info("🚀 SECURE HANDSHAKE SUCCESS")
                public_key_handler.promote_temp_key()
                self._send_ha_service_settings(client)
                self._send_spotify_details(client)
                self._send_seawater_details(client)

    def _send_config_response(self, client, key, data):
        options = self._get_options()
        mailbox_id = options.get("WolsCA_MailboxID", "88889999")
        envelope = {
            "header": {
                "from": options.get("WolsCA_UploaderName", "ha_uploader"),
                "timestamp": int(time.time()),
                "encrypted": public_key_handler.is_public_key_active()
            },
            "payload": data
        }
        topic = get_scrambled_path_helper(mailbox_id, key)
        client.publish(topic, json.dumps(envelope), retain=False)

    def _send_ha_service_settings(self, client):
        options = self._get_options()
        data = {
            "MqttUser": active_mqtt_user,
            "MqttPassword": active_mqtt_password,
            "MailboxID": options.get("WolsCA_MailboxID", "88889999")
        }
        self._send_config_response(client, "HAServiceSettings", data)

    def _send_spotify_details(self, client):
        options = self._get_options()
        if not options.get("SpotifyEnabled", False):
            self._send_config_response(client, "SpotifyDetails", {"Enabled": False})
            return

        sets = []
        for i in range(1, int(options.get("PlaylistSets", 0)) + 1):
            src, tgt = secrets_handler.get_secret(f"SourceID{i}"), secrets_handler.get_secret(f"TargetID{i}")
            if src and tgt:
                sets.append({"source": src, "target": tgt, "play_time": secrets_handler.get_secret(f"PlayTime{i}")})

        self._send_config_response(client, "SpotifyDetails", {"Enabled": True, "Sets": sets})

    def _send_seawater_details(self, client):
        options = self._get_options()
        if not options.get("SeaWaterEnabled", False):
            self._send_config_response(client, "SeaWaterDetails", {"Enabled": False})
            return

        pos = [secrets_handler.get_secret(f"Position{i}") for i in range(1, int(options.get("SeaWaterNumber", 0)) + 1)]
        pos = [p for p in pos if p] # Filter lege posities

        self._send_config_response(client, "SeaWaterDetails", {"Enabled": True, "Positions": pos})

def handle_mqtt_message(client, msg, uploader_version):
    global _router_instance
    if _router_instance is None:
        _router_instance = MQTTMessageRouter(uploader_version)
    return _router_instance.route_message(client, msg)