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

def get_scrambled_path_helper(product_key, sub_topic):
    mb_hash = hashlib.sha256(str(product_key).encode()).hexdigest()[:16]
    sub_hash = hashlib.sha256(str(sub_topic).encode()).hexdigest()[:16]
    return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}".lower()

def parse_google_maps_coordinates(coord_str):
    if not coord_str: return None
    coord_str = coord_str.strip()
    decimal_match = re.match(r"^\s*(-?\d+\.\d+)[,\s]+(-?\d+\.\d+)\s*$", coord_str)
    if decimal_match: return f"{decimal_match.group(1)}, {decimal_match.group(2)}"
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
    if not _router_instance: return
    product_key = _router_instance.product_key
    
    dev_seawater = {"identifiers": [f"wols_ca_{product_key}_sw"], "name": "Wols CA SeaWater System", "manufacturer": "Wols CA"}
    dev_spotify = {"identifiers": [f"wols_ca_{product_key}_sp"], "name": "Wols CA Spotify System", "manufacturer": "Wols CA"}

    sw_mailbox = get_scrambled_path_helper(product_key, "SeaWaterDetails")
    for i in range(1, 101):
        sw_payload = {"name": f"SW Position {i}", "unique_id": f"wols_ca_sw_pos_{i}", "icon": "mdi:map-marker-distance", "command_topic": f"{sw_mailbox}/set/Position{i}", "state_topic": f"{sw_mailbox}/state/Position{i}", "device": dev_seawater}
        client.publish(f"homeassistant/text/wols_ca/sw_pos_{i}/config".lower(), json.dumps(sw_payload), retain=True)

    spot_mailbox = get_scrambled_path_helper(product_key, "SpotifyDetails")
    for i in range(1, 25):
        for field in ["SourceID", "TargetID", "PlayTime"]:
            spot_payload = {"name": f"Spotify {field} {i}", "unique_id": f"wols_ca_spot_{field.lower()}_{i}", "icon": "mdi:music-box-outline", "command_topic": f"{spot_mailbox}/set/{field}{i}", "state_topic": f"{spot_mailbox}/state/{field}{i}", "device": dev_spotify}
            client.publish(f"homeassistant/text/wols_ca/spot_{field.lower()}_{i}/config".lower(), json.dumps(spot_payload), retain=True)
    logging.info("🚀 Dashboard Discovery: Secure entities registered via Dynamic Product Key.")

class MQTTMessageRouter:
    def __init__(self, uploader_version, product_key):
        self.uploader_version = uploader_version
        self.product_key = product_key
        self.logger = logging.getLogger(__name__)

    def route_message(self, client, msg):
        topic = msg.topic.lower()
        try:
            if not msg.payload: return False
            payload_str = msg.payload.decode().strip()
        except Exception: return False
        
        request_path = get_scrambled_path_helper(self.product_key, "requests")

        if topic == "wols_ca_mqtt/keys/public":
            public_key_handler.StepA_Process_PublicKey(client, msg, active_mqtt_user, active_mqtt_password, "localhost")
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
                if sig.lower() == raw_hash.hexdigest().lower() or sig == base64.b64encode(raw_hash.digest()).decode('utf-8'):
                    data = json.loads(data_str)
                    node_id = data.get("id")
                    temp = data.get("temperature")
                    ha_base_topic = f"wols_ca_mqtt/ha/seawater/temp/{node_id}".lower()
                    client.publish(ha_base_topic, str(temp), retain=True)
                    self.logger.info(f"📍 SeaWater data securely forwarded to HA for: {data.get('name')} ({temp}°C)")
            except Exception as e: pass
            return True

        key_rotation_hash = hashlib.sha256("key_rotation".encode()).hexdigest()[:16]
        if key_rotation_hash in topic:
            try:
                payload_data = json.loads(payload_str)
                if new_key := payload_data.get("payload", {}).get("new_public_key"):
                    public_key_handler.update_rolling_key(new_key)
            except Exception: pass
            return True

        if "/set/" in topic:
            field_name = topic.split("/")[-1]
            value_to_store = payload_str
            if "Position" in field_name:
                if parsed_val := parse_google_maps_coordinates(payload_str): value_to_store = parsed_val
                else: return True 

            if secrets_handler.update_secret(field_name, value_to_store):
                state_topic = topic.replace("/set/", "/state/")
                client.publish(state_topic, value_to_store, retain=True)
                if "Position" in field_name: self._send_seawater_details(client)
                else: self._send_spotify_details(client)
            return True
        return False

    def _send_config_response(self, client, key, data):
        is_encrypted = public_key_handler.active_public_key is not None
        inner_payload_str = json.dumps(data)
        envelope = {"header": {"from": "ha_uploader", "timestamp": int(time.time()), "encrypted": is_encrypted}}
        
        if is_encrypted:
            try:
                encrypted_bytes = public_key_handler.active_public_key.encrypt(
                    inner_payload_str.encode('utf-8'),
                    padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                )
                envelope[key] = base64.b64encode(encrypted_bytes).decode('utf-8')
            except ValueError:
                envelope["header"]["encrypted"] = False
                envelope[key] = data
        else: envelope[key] = data
            
        topic = get_scrambled_path_helper(self.product_key, key)
        client.publish(topic, json.dumps(envelope), qos=1, retain=True)

    def _send_ha_service_settings(self, client):
        self._send_config_response(client, "HAServiceSettings", {"MqttUser": active_mqtt_user, "MqttPassword": active_mqtt_password, "ProductKey": self.product_key})

    def _send_seawater_details(self, client):
        posities = []
        for i in range(1, int(secrets_handler.get_secret("SeaWaterNumber") or 0) + 1):
            if parsed_val := parse_google_maps_coordinates(secrets_handler.get_secret(f"Position{i}")):
                posities.append({"id": i, "value": parsed_val})
        self._send_config_response(client, "SeaWaterDetails", {"Enabled": True, "Sensors": posities, "Timestamp": int(time.time())})

    def _send_spotify_details(self, client):
        sets = []
        for i in range(1, int(secrets_handler.get_secret("PlaylistSets") or 0) + 1):
            src, tgt, tm = secrets_handler.get_secret(f"SourceID{i}"), secrets_handler.get_secret(f"TargetID{i}"), secrets_handler.get_secret(f"PlayTime{i}")
            if src and tgt: sets.append({"source": src, "target": tgt, "play_time": tm})
        self._send_config_response(client, "SpotifyDetails", {"Enabled": True, "Sets": sets, "Timestamp": int(time.time())})

def handle_mqtt_message(client, msg, uploader_version):
    global _router_instance
    if _router_instance: return _router_instance.route_message(client, msg)