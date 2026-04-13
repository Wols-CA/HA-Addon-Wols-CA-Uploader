import json
import logging
import os
import time
import hashlib
import re
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

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
    mb_hash = hashlib.sha256(str(mailbox_id).encode()).hexdigest()[:16]
    sub_hash = hashlib.sha256(str(sub_topic).encode()).hexdigest()[:16]
    return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}"

def parse_google_maps_coordinates(coord_str):
    if not coord_str:
        return None
    coord_str = coord_str.strip()
    
    decimal_match = re.match(r"^\s*(-?\d+\.\d+)[,\s]+(-?\d+\.\d+)\s*$", coord_str)
    if decimal_match:
        return f"{decimal_match.group(1)}, {decimal_match.group(2)}"
        
    dms_pattern = r"(\d+)[°\s]+(\d+)['\s]+([\d\.]+)(?:\"|''|\s)*([NS])[,\s]*(\d+)[°\s]+(\d+)['\s]+([\d\.]+)(?:\"|''|\s)*([EW])"
    dms_match = re.search(dms_pattern, coord_str, re.IGNORECASE)
    
    if dms_match:
        lat_d, lat_m, lat_s, lat_dir, lon_d, lon_m, lon_s, lon_dir = dms_match.groups()
        lat = float(lat_d) + float(lat_m)/60 + float(lat_s)/3600
        if lat_dir.upper() == 'S': lat = -lat
        lon = float(lon_d) + float(lon_m)/60 + float(lon_s)/3600
        if lon_dir.upper() == 'W': lon = -lon
        return f"{round(lat, 6)}, {round(lon, 6)}"
        
    return None

def publish_dashboard_discovery(client):
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
        
        options = self._get_options()
        mailbox_id = options.get("WolsCA_MailboxID", "88889999")
        request_path = get_scrambled_path_helper(mailbox_id, "requests")

        if topic == "wols_ca_mqtt/keys/public":
            url = options.get("mqtt_broker", "localhost")
            public_key_handler.StepA_Process_PublicKey(client, msg, active_mqtt_user, active_mqtt_password, url)
            return True
            
        if topic == "wols_ca_mqtt/admin/service_verify":
            public_key_handler.StepC_Verify_Service_And_Respond(client, msg)
            return True
            
        if topic == "wols_ca_mqtt/admin/password_ack":
            public_key_handler.handle_ack(payload_str)
            if payload_str == "ACK":
                self.logger.info("🚀 C++ Service is Ready! Actively pushing