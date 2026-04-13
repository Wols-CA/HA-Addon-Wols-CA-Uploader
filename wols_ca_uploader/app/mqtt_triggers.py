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
                self.logger.info("🚀 C++ Service is Ready! Actively pushing Wols CA Configuration...")
                self._send_ha_service_settings(client)
                self._send_spotify_details(client)
                self._send_seawater_details(client)
            return True
        
        if topic == request_path:
            if "REQ_CONFIG_SEAWATER" in payload_str:
                self.logger.info("📥 C++ Service requested SeaWater data. Resending from secrets...")
                self._send_seawater_details(client)
            return True

        sw_data_hash = hashlib.sha256("seawater_sensor_data".encode()).hexdigest()[:16]
        if sw_data_hash in topic:
            try:
                envelope = json.loads(payload_str)
                data_str = envelope.get("data", "")
                sig = envelope.get("signature", "")
                
                raw_hash = hashlib.sha256((data_str + active_mqtt_password).encode('utf-8'))
                expected_hex = raw_hash.hexdigest().lower()
                expected_b64 = base64.b64encode(raw_hash.digest()).decode('utf-8')
                
                if sig.lower() == expected_hex or sig == expected_b64:
                    data = json.loads(data_str)
                    node_id = data.get("id")
                    temp = data.get("temperature")
                    maps_url = data.get("google_maps")
                    todo_url = data.get("things_to_do")
                    
                    markdown_buttons = (
                        f"[![Google Maps](https://img.shields.io/badge/Google%20Maps-Open-4285F4?style=for-the-badge&logo=googlemaps&logoColor=white)]({maps_url})  "
                        f"[![Things to Do](https://img.shields.io/badge/Things%20to%20Do-Explore-FF69B4?style=for-the-badge&logo=tripadvisor&logoColor=white)]({todo_url})"
                    )

                    attributes = {
                        "Location Name": data.get("name"),
                        "Latitude": data.get("latitude"),
                        "Longitude": data.get("longitude"),
                        "Google Maps": maps_url,
                        "Things to Do": todo_url,
                        "Dashboard Buttons": markdown_buttons,
                        "Last Updated": time.strftime('%Y-%m-%d %H:%M:%S')
                    }
                    
                    ha_base_topic = f"wols_ca_mqtt/ha/seawater/temp/{node_id}"
                    client.publish(ha_base_topic, str(temp), retain=True)
                    client.publish(f"{ha_base_topic}/attributes", json.dumps(attributes), retain=True)
                    
                    self.logger.info(f"📍 SeaWater data securely forwarded to HA for: {data.get('name')} ({temp}°C)")
                else:
                    self.logger.error("Fake SeaWater data rejected! Signature mismatch.")
            except Exception as e:
                self.logger.error(f"Error parsing SeaWater data: {e}")
            return True

        key_rotation_hash = hashlib.sha256("key_rotation".encode()).hexdigest()[:16]
        if key_rotation_hash in topic:
            try:
                payload_data = json.loads(payload_str)
                new_key = payload_data.get("payload", {}).get("new_public_key")
                if new_key:
                    public_key_handler.update_rolling_key(new_key)
            except Exception as e:
                self.logger.error(f"Error processing Rolling Key: {e}")
            return True

        if "/set/" in topic:
            field_name = topic.split("/")[-1]
            value_to_store = payload_str
            
            if "Position" in field_name:
                parsed_val = parse_google_maps_coordinates(payload_str)
                if parsed_val is not None:
                    value_to_store = parsed_val
                else:
                    self.logger.error(f"❌ Ongeldige coördinaten invoer geweigerd: {payload_str}")
                    return True 

            if secrets_handler.update_secret(field_name, value_to_store):
                self.logger.info(f"📍 Securely stored {field_name}")
                state_topic = topic.replace("/set/", "/state/")
                client.publish(state_topic, value_to_store, retain=True)

                if "Position" in field_name:
                    self._send_seawater_details(client)
                else:
                    self._send_spotify_details(client)
            return True

        return False

    def _send_config_response(self, client, key, data):
        options = self._get_options()
        mailbox_id = options.get("WolsCA_MailboxID", "88889999")
        
        is_encrypted = public_key_handler.active_public_key is not None
        
        inner_payload_str = json.dumps({ key: data })
        final_payload = { key: data } 
        
        if is_encrypted:
            try:
                encrypted_bytes = public_key_handler.active_public_key.encrypt(
                    inner_payload_str.encode('utf-8'),
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                final_payload = base64.b64encode(encrypted_bytes).decode('utf-8')
            except ValueError as e:
                self.logger.warning(f"⚠️ Payload te groot voor pure RSA. Terugval naar 1x encryptie: {e}")
                is_encrypted = False

        envelope = {
            "header": {
                "from": options.get("WolsCA_UploaderName", "ha_uploader"),
                "timestamp": int(time.time()),
                "encrypted": is_encrypted
            },
            "payload": final_payload 
        }
        
        topic = get_scrambled_path_helper(mailbox_id, key)
        client.publish(topic, json.dumps(envelope), qos=1, retain=True)

    def _send_ha_service_settings(self, client):
        options = self._get_options()
        data = {
            "MqttUser": active_mqtt_user,
            "MqttPassword": active_mqtt_password,
            "MailboxID": options.get("WolsCA_MailboxID", "88889999")
        }
        self._send_config_response(client, "HAServiceSettings", data)

    def _send_seawater_details(self, client):
        num_sensors = secrets_handler.get_secret("SeaWaterNumber")
        if num_sensors is None:
            num_sensors = 0
        
        num_sensors = int(num_sensors)
        posities = []
        
        for i in range(1, num_sensors + 1):
            raw_val = secrets_handler.get_secret(f"Position{i}")
            parsed_val = parse_google_maps_coordinates(raw_val)
            if parsed_val:
                posities.append({"id": i, "value": parsed_val})

        payload = {
            "Enabled": True,
            "Sensors": posities,
            "Timestamp": int(time.time())
        }
        self._send_config_response(client, "SeaWaterDetails", payload)

    def _send_spotify_details(self, client):
        options = self._get_options()
        if not options.get("SpotifyEnabled", False):
            self._send_config_response(client, "SpotifyDetails", {"Enabled": False})
            return

        sets = []
        num_sets = int(options.get("PlaylistSets", 0))
        for i in range(1, num_sets + 1):
            src = secrets_handler.get_secret(f"SourceID{i}")
            tgt = secrets_handler.get_secret(f"TargetID{i}")
            tm  = secrets_handler.get_secret(f"PlayTime{i}")
            if src and tgt:
                sets.append({"source": src, "target": tgt, "play_time": tm})

        payload = {
            "Enabled": True, 
            "Sets": sets,
            "Timestamp": int(time.time())
        }
        self._send_config_response(client, "SpotifyDetails", payload)

def handle_mqtt_message(client, msg, uploader_version):
    global _router_instance
    if _router_instance is None:
        _router_instance = MQTTMessageRouter(uploader_version)
    return _router_instance.route_message(client, msg)
