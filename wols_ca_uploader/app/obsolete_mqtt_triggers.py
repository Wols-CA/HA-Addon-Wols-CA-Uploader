import json
import logging
import os
import time
import hashlib
import re
import base64

import secrets_handler
import public_key_handler

active_mqtt_user = None
active_mqtt_password = None
active_mqtt_broker = "localhost" 
_router_instance = None

# WOLS CA SHADOW REGISTRY
shadow_registry = {}

def register_new_session(client_ext, server_name, new_session_topic):
    """Clears old MQTT traces on External Broker (Trace Wiping)"""
    global shadow_registry
    old_topic = shadow_registry.get(server_name)
    if old_topic and old_topic != new_session_topic:
        logging.info(f"🧹 Trace Wiping Active: Old external session traces of '{server_name}' destroyed.")
        for key in ["haservicesettings", "seawaterdetails", "spotifydetails"]:
            client_ext.publish(f"{old_topic}/{key}", "", retain=True)
            
    shadow_registry[server_name] = new_session_topic
    logging.info(f"🔗 Airgap Bridge: '{server_name}' linked to external channel: {new_session_topic}")

def set_mqtt_credentials(user, password, broker="localhost"):
    global active_mqtt_user, active_mqtt_password, active_mqtt_broker
    active_mqtt_user = user
    active_mqtt_password = password
    active_mqtt_broker = broker

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

def publish_dashboard_discovery(client_int):
    """Publishes Discovery ONLY to the Internal (HA) Broker"""
    if not _router_instance: return
    product_key = _router_instance.product_key
    
    dev_seawater = {"identifiers": [f"wols_ca_{product_key}_sw_system"], "name": "Wols CA SeaWater System", "manufacturer": "Wols CA", "model": "NG Security Bridge"}
    dev_spotify = {"identifiers": [f"wols_ca_{product_key}_sp_system"], "name": "Wols CA Spotify System", "manufacturer": "Wols CA", "model": "NG Security Bridge"}

    sw_mailbox = get_scrambled_path_helper(product_key, "SeaWaterDetails")
    for i in range(1, 101):
        cfg_payload = {"name": f"SW Config Position {i}", "unique_id": f"wols_ca_sw_pos_{i}", "icon": "mdi:map-marker-distance", "command_topic": f"{sw_mailbox}/set/Position{i}", "state_topic": f"{sw_mailbox}/state/Position{i}", "device": dev_seawater}
        client_int.publish(f"homeassistant/text/wols_ca/sw_pos_{i}/config".lower(), json.dumps(cfg_payload), retain=True)

        sensor_payload = {"name": f"Sea Temperature {i}", "unique_id": f"wols_ca_sw_temp_{i}", "state_topic": f"wols_ca/sensor/sw_temp_{i}/state", "unit_of_measurement": "°C", "device_class": "temperature", "value_template": "{{ value_json.temp }}", "device": dev_seawater, "icon": "mdi:thermometer-water"}
        client_int.publish(f"homeassistant/sensor/wols_ca/sw_temp_{i}/config".lower(), json.dumps(sensor_payload), retain=True)

    spot_mailbox = get_scrambled_path_helper(product_key, "SpotifyDetails")
    for i in range(1, 25):
        for field in ["SourceID", "TargetID", "PlayTime"]:
            spot_payload = {"name": f"Spotify {field} {i}", "unique_id": f"wols_ca_spot_{field.lower()}_{i}", "icon": "mdi:music-box-outline", "command_topic": f"{spot_mailbox}/set/{field}{i}", "state_topic": f"{spot_mailbox}/state/{field}{i}", "device": dev_spotify}
            client_int.publish(f"homeassistant/text/wols_ca/spot_{field.lower()}_{i}/config".lower(), json.dumps(spot_payload), retain=True)
            
    logging.info("🛡️ Dashboard Discovery: Secured entities registered internally.")

class MQTTMessageRouter:
    def __init__(self, uploader_version, product_key):
        self.uploader_version = uploader_version
        self.product_key = product_key
        self.logger = logging.getLogger(__name__)

    def route_message(self, client_ext, client_int, msg):
        topic = msg.topic.lower()
        try:
            if not msg.payload: return False
            payload_str = msg.payload.decode().strip()
        except Exception: return False
        
        # HANDSHAKE (EXTERNAL)
        if topic == "wols_ca_mqtt/keys/public":
            public_key_handler.StepA_Process_PublicKey(client_ext, msg, active_mqtt_user, active_mqtt_password, active_mqtt_broker, self.uploader_version)
            return True
            
        if topic == "wols_ca_mqtt/admin/service_verify":
            public_key_handler.StepC_Verify_Service_And_Respond(client_ext, msg)
            return True
            
        if topic == "wols_ca_mqtt/admin/password_ack":
            public_key_handler.handle_ack(payload_str)
            if payload_str == "ACK":
                self.logger.info("🚀 Actively pushing Wols CA Configuration to Shadow Registry Sessions...")
                self._send_ha_service_settings(client_ext)
                self._send_spotify_details(client_ext)
                self._send_seawater_details(client_ext)
            return True
        
        if topic.startswith("wols_ca_mqtt/session/") and topic.endswith("/requests"):
            if "REQ_CONFIG_SEAWATER" in payload_str:
                self._send_seawater_details(client_ext)
            return True

        # CONFIGURATION INPUT FROM HA (INTERNAL)
        # Note: If HA sends a config update, it arrives on client_int (or web UI). 
        # For simplicity, if it arrives here via client_ext it means the C++ node confirms it.
        if "/set/" in topic:
            field_name = topic.split("/")[-1]
            value_to_store = payload_str
            if "Position" in field_name:
                if parsed_val := parse_google_maps_coordinates(payload_str): value_to_store = parsed_val
                else: return True 

            if secrets_handler.update_secret(field_name, value_to_store):
                # Send confirmation to INTERNAL HA
                state_topic = topic.replace("/set/", "/state/")
                client_int.publish(state_topic, value_to_store, retain=True)
                
                if "Position" in field_name: self._send_seawater_details(client_ext)
                else: self._send_spotify_details(client_ext)
            return True
        return False

    def _send_config_response(self, client_ext, key, data):
        is_encrypted = public_key_handler.active_public_key is not None
        inner_payload_str = json.dumps(data)
        envelope = {"header": {"from": "ha_uploader", "timestamp": int(time.time()), "encrypted": is_encrypted}}
        
        if is_encrypted:
            try:
                envelope[key] = public_key_handler.bulk_encrypt_for_service(inner_payload_str)
            except Exception as e:
                self.logger.error(f"Error during bulk encryption: {e}")
                envelope["header"]["encrypted"] = False
                envelope[key] = data
        else: envelope[key] = data
            
        global shadow_registry
        if not shadow_registry:
            topic = get_scrambled_path_helper(self.product_key, key)
            client_ext.publish(topic, json.dumps(envelope), qos=1, retain=False)
        else:
            for server_name, session_topic in shadow_registry.items():
                dynamic_topic = f"{session_topic}/{key.lower()}"
                client_ext.publish(dynamic_topic, json.dumps(envelope), qos=1, retain=False)

    def _send_ha_service_settings(self, client_ext):
        self._send_config_response(client_ext, "HAServiceSettings", {"MqttUser": active_mqtt_user, "MqttPassword": active_mqtt_password, "ProductKey": self.product_key})

    def _send_seawater_details(self, client_ext):
        posities = []
        for i in range(1, int(secrets_handler.get_secret("SeaWaterNumber") or 0) + 1):
            if parsed_val := parse_google_maps_coordinates(secrets_handler.get_secret(f"Position{i}")):
                posities.append({"id": i, "value": parsed_val})
        self._send_config_response(client_ext, "SeaWaterDetails", {"Enabled": True, "Sensors": posities, "Timestamp": int(time.time())})

    def _send_spotify_details(self, client_ext):
        sets = []
        for i in range(1, int(secrets_handler.get_secret("PlaylistSets") or 0) + 1):
            src, tgt, tm = secrets_handler.get_secret(f"SourceID{i}"), secrets_handler.get_secret(f"TargetID{i}"), secrets_handler.get_secret(f"PlayTime{i}")
            if src and tgt: sets.append({"source": src, "target": tgt, "play_time": tm})
        self._send_config_response(client_ext, "SpotifyDetails", {"Enabled": True, "Sets": sets, "Timestamp": int(time.time())})


def handle_mqtt_message(client_ext, client_int, msg, uploader_version):
    global _router_instance
    topic = msg.topic.lower()
    
    # --- WOLS CA BRIDGE: Read from External, Decrypt, Write to Internal ---
    if "/seawaterdetails/state/position" in topic:
        try:
            b64_payload = msg.payload.decode().strip()
            
            # 1. Decrypt Mutual RSA
            decrypted_str = public_key_handler.decrypt_from_service(b64_payload)
            if not decrypted_str: return True

            # 2. Parse Envelope
            envelope = json.loads(decrypted_str)
            raw_payload = envelope.get("payload", "")
            signature = envelope.get("signature", "")

            # 3. Verify Signature
            expected_sig = hashlib.sha256((raw_payload + (active_mqtt_password or "")).encode()).hexdigest()
            if signature != expected_sig:
                logging.error("Security Alert: Invalid signature! Dropping packet.")
                return True

            # 4. Process Verified Data
            data = json.loads(raw_payload)
            sensor_id = data.get("id") # e.g., "Position1"
            pos_num = sensor_id.replace("Position", "") 
            
            # 5. Publish to INTERNAL HA Broker (Airgap Crossing)
            state_topic = f"wols_ca/sensor/sw_temp_{pos_num}/state"
            client_int.publish(state_topic, json.dumps({"temp": data.get("temperature")}), retain=True)

            # 6. Store safely in Vault
            secrets_handler.update_secret(f"State_{sensor_id}", raw_payload)
            logging.info(f"🛡️ Airgap Crossed: Ext Data -> Int Sensor ({data.get('location')} {data.get('temperature')}°C)")
            
            return True

        except Exception as e:
            logging.error(f"Error processing C++ SeaWater state across bridge: {e}")
            return True

    if _router_instance: 
        return _router_instance.route_message(client_ext, client_int, msg)