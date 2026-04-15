import json
import hashlib
import time
import re
import logging
from mqtt_util import MQTTBaseClient
import public_key_handler
import secrets_handler

# ==============================================================================
# WOLS CA IT SECURITY NG - EXTERNAL BRIDGE (DMZ)
# ==============================================================================

# WOLS CA SHADOW REGISTRY
# Tracks active sessions per Service Node to push dynamic configurations
shadow_registry = {}

def register_new_session(client_ext, server_name, new_session_topic):
    """Clears old MQTT traces on External Broker and registers the new session."""
    global shadow_registry
    old_topic = shadow_registry.get(server_name)
    if old_topic and old_topic != new_session_topic:
        # Wipe old retained configuration messages to maintain a clean Zero-Trust environment
        for key in ["haservicesettings", "seawaterdetails", "spotifydetails"]:
            client_ext.publish(f"{old_topic}/{key}", "", retain=True)
            
    shadow_registry[server_name] = new_session_topic
    logging.info(f"🔄 Registered active session for {server_name}: {new_session_topic}")

class MQTTExternalBridge(MQTTBaseClient):
    def __init__(self, client_id, broker_ip, port, user, password, product_key, data_callback, uploader_version="1.0.0", service_id=None, ser_config=None):
        super().__init__(client_id, broker_ip, port, user, password)
        self.product_key = product_key
        self.ext_password = password
        self.ext_user = user
        self.data_callback = data_callback # The 'mailbox' to the internal network
        self.uploader_version = uploader_version
        self.service_id = service_id # WolsCA Hub Identity
        
        # Used to pass the definitive production credentials to the C++ node during the handshake
        self.ser_config = ser_config if ser_config else {}

    def on_successful_connect(self):
        self.logger.info("🌐 EXTERNAL: Zero-Trust DMZ ready. Subscribing to secure channels...")
        
        # Subscribe to the new Phase 5 Honeytoken Handshake paths
        self.client.subscribe([
            ("wols_ca_mqtt/admin/login", 1),              # Initial login & Challenge request
            ("wols_ca_mqtt/admin/challenge_response", 1), # Incoming NACK/ACK from the Service
            ("wols_ca_mqtt/session/#", 1)                 # Operational Data & Config Requests
        ])

    def on_message(self, client, userdata, msg):
        topic = msg.topic.lower()
        try:
            if not msg.payload: return
            payload_str = msg.payload.decode().strip()
        except Exception: return
        
        # --- 1. PROCESS INCOMING SECURE SEAWATER DATA (OPERATIONAL) ---
        if "/seawaterdetails/state/position" in topic:
            self._process_encrypted_seawater(payload_str)
            return

        # --- 2. PHASE 5: WOLS CA HONEYTOKEN HANDSHAKE ---
        if topic == "wols_ca_mqtt/admin/login":
            self.logger.info("📥 Incoming Service Login detected. Initiating Phase 5 Challenge...")
            # We pass the production credentials down to the handler. 
            # They will ONLY be sent if the Service passes the Honeytoken test.
            public_key_handler.StepA_Process_Login_And_Challenge(
                self.client, 
                msg, 
                prod_url=self.ser_config.get("broker", self.broker_ip), 
                prod_port=self.ser_config.get("port", self.port), 
                prod_user=self.ser_config.get("user", self.ext_user), 
                prod_pass=self.ser_config.get("pass", self.ext_password)
            )
            return
            
        if topic == "wols_ca_mqtt/admin/challenge_response":
            public_key_handler.StepB_Process_Response(self.client, msg)
            return
        
        # --- 3. EPHEMERAL/OPERATIONAL CHANNEL REQUESTS ---
        if topic.startswith("wols_ca_mqtt/session/") and topic.endswith("/requests"):
            if "REQ_CONFIG" in payload_str:
                # Extract CPU ID / Server Name from the topic: wols_ca_mqtt/session/{cpu_id}/requests
                try:
                    server_name = topic.split("/")[2]
                    session_topic = f"wols_ca_mqtt/session/{server_name}"
                    
                    self.logger.info(f"📥 C++ Service ({server_name}) requested configuration sync.")
                    register_new_session(self.client, server_name, session_topic)
                    
                    # Push all configurations to the new verified session
                    self._send_ha_service_settings()
                    self._send_spotify_details()
                    self._send_seawater_details()
                except IndexError:
                    self.logger.error("Malformed session request topic.")
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
        
        # WOLS CA FIX: Use self.service_id (e.g. WolsHub01) in the header
        envelope = {
            "header": {
                "from": self.service_id, 
                "timestamp": int(time.time()), 
                "encrypted": is_encrypted
            }
        }
        
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
                self.logger.info(f"📤 Pushed {key} to {dynamic_topic}")

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