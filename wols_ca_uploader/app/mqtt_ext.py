import json
import hashlib
import time
import re
from mqtt_util import MQTTBaseClient
import public_key_handler
import secrets_handler

# WOLS CA SHADOW REGISTRY
shadow_registry = {}

def register_new_session(client_ext, server_name, new_session_topic):
    """Clears old MQTT traces on External Broker (Trace Wiping)"""
    global shadow_registry
    old_topic = shadow_registry.get(server_name)
    if old_topic and old_topic != new_session_topic:
        for key in ["haservicesettings", "seawaterdetails", "spotifydetails"]:
            client_ext.publish(f"{old_topic}/{key}", "", retain=True)
            
    shadow_registry[server_name] = new_session_topic

class MQTTExternalBridge(MQTTBaseClient):
    def __init__(self, client_id, broker_ip, port, user, password, product_key, data_callback, uploader_version="0.7.0"):
        super().__init__(client_id, broker_ip, port, user, password)
        self.product_key = product_key
        self.ext_password = password
        self.ext_user = user
        self.data_callback = data_callback # The 'mailbox' to the internal network
        self.uploader_version = uploader_version

    def on_successful_connect(self):
        self.logger.info("🌐 EXTERNAL: Zero-Trust Zone ready. Subscribing to public channels...")
        
        # Subscribe to public handshake paths and dynamic session paths
        self.client.subscribe([
            ("wols_ca_mqtt/keys/public", 1),
            ("wols_ca_mqtt/admin/service_verify", 1),
            ("wols_ca_mqtt/admin/password_ack", 1),
            ("wols_ca_mqtt/session/#", 1)
        ])
        
        # Trigger any connected services to start the handshake
        self.publish("wols_ca_mqtt/admin/request_key", "STARTUP_SYNC", retain=False)

    def on_message(self, client, userdata, msg):
        topic = msg.topic.lower()
        try:
            if not msg.payload: return
            payload_str = msg.payload.decode().strip()
        except Exception: return
        
        # --- 1. PROCESS INCOMING SECURE SEAWATER DATA ---
        if "/seawaterdetails/state/position" in topic:
            self._process_encrypted_seawater(payload_str)
            return

        # --- 2. WOLS CA HANDSHAKE LOGIC ---
        if topic == "wols_ca_mqtt/keys/public":
            public_key_handler.StepA_Process_PublicKey(
                self.client, msg, self.ext_user, self.ext_password, 
                self.broker_ip, self.uploader_version
            )
            return
            
        if topic == "wols_ca_mqtt/admin/service_verify":
            # Override register session callback dynamically for Step C
            import public_key_handler
            import mqtt_ext
            mqtt_ext.register_new_session = register_new_session
            
            public_key_handler.StepC_Verify_Service_And_Respond(self.client, msg)
            return
            
        if topic == "wols_ca_mqtt/admin/password_ack":
            public_key_handler.handle_ack(payload_str)
            if payload_str == "ACK":
                self.logger.info("🚀 Actively pushing Wols CA Configuration to Shadow Registry Sessions...")
                self._send_ha_service_settings()
                self._send_spotify_details()
                self._send_seawater_details()
            return
        
        # --- 3. EPHEMERAL CHANNEL REQUESTS ---
        if topic.startswith("wols_ca_mqtt/session/") and topic.endswith("/requests"):
            if "REQ_CONFIG_SEAWATER" in payload_str:
                self.logger.info("📥 C++ Service requested SeaWater data on Ephemeral Channel. Resending...")
                self._send_seawater_details()
            return

    def _process_encrypted_seawater(self, b64_payload):
        """1. Decrypt Mutual RSA  2. Verify Signature  3. Forward via Airgap Callback"""
        try:
            decrypted_str = public_key_handler.decrypt_from_service(b64_payload)
            if not decrypted_str: return

            envelope = json.loads(decrypted_str)
            raw_payload = envelope.get("payload", "")
            signature = envelope.get("signature", "")

            # Integrity check against manipulation
            expected_sig = hashlib.sha256((raw_payload + (self.ext_password or "")).encode()).hexdigest()
            if signature != expected_sig:
                self.logger.error("🚨 SECURITY: Invalid signature on SeaWater data! Dropping.")
                return

            data = json.loads(raw_payload)
            sensor_id = data.get("id") # e.g., "Position1"
            pos_num = sensor_id.replace("Position", "") 
            temperature = data.get("temperature")

            # Store the raw string safely for Web UI
            secrets_handler.update_secret(f"State_{sensor_id}", raw_payload)
            
            # Transfer clean data to the safe zone (Internal Broker) via the callback
            self.data_callback(pos_num, temperature)
            self.logger.info(f"🌐 EXTERNAL: Data verified for Position {pos_num}. Sent to Airgap.")

        except Exception as e:
            self.logger.error(f"Error processing encrypted data: {e}")

    # --- WOLS CA CONFIGURATION PUSH LOGIC ---
    def _get_scrambled_path(self, sub_topic):
        mb_hash = hashlib.sha256(str(self.product_key).encode()).hexdigest()[:16]
        sub_hash = hashlib.sha256(str(sub_topic).encode()).hexdigest()[:16]
        return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}".lower()

    def _send_config_response(self, key, data):
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
        else: 
            envelope[key] = data
            
        global shadow_registry
        if not shadow_registry:
            topic = self._get_scrambled_path(key)
            self.publish(topic, json.dumps(envelope), retain=False)
        else:
            for server_name, session_topic in shadow_registry.items():
                dynamic_topic = f"{session_topic}/{key.lower()}"
                self.publish(dynamic_topic, json.dumps(envelope), retain=False)

    def _send_ha_service_settings(self):
        self._send_config_response("HAServiceSettings", {
            "MqttUser": self.ext_user, 
            "MqttPassword": self.ext_password, 
            "ProductKey": self.product_key
        })

    def _send_seawater_details(self):
        def parse_coords(coord_str):
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

        posities = []
        for i in range(1, int(secrets_handler.get_secret("SeaWaterNumber") or 0) + 1):
            if parsed_val := parse_coords(secrets_handler.get_secret(f"Position{i}")):
                posities.append({"id": i, "value": parsed_val})
        self._send_config_response("SeaWaterDetails", {"Enabled": True, "Sensors": posities, "Timestamp": int(time.time())})

    def _send_spotify_details(self):
        sets = []
        for i in range(1, int(secrets_handler.get_secret("PlaylistSets") or 0) + 1):
            src = secrets_handler.get_secret(f"SourceID{i}")
            tgt = secrets_handler.get_secret(f"TargetID{i}")
            tm = secrets_handler.get_secret(f"PlayTime{i}")
            if src and tgt: sets.append({"source": src, "target": tgt, "play_time": tm})
        self._send_config_response("SpotifyDetails", {"Enabled": True, "Sets": sets, "Timestamp": int(time.time())})