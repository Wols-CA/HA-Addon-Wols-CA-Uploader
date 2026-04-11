import json
import logging
import os
import time

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

# --- STANDALONE DASHBOARD DISCOVERY ---
def publish_dashboard_discovery(client):
    """Creates secure trigger buttons in Home Assistant via MQTT Discovery"""
    device_info = {
        "identifiers": ["wols_ca_vault"],
        "name": "wols_ca Configuration Vault",
        "manufacturer": "Wols"
    }

    # Create Reload and Factory Reset buttons (The Triggers)
    buttons = {
        "SpotifyReload": ("wols_ca/admin/command/SpotifyReload", "mdi:reload"),
        "SpotifyReset": ("wols_ca/admin/command/SpotifyReset", "mdi:delete-alert"),
        "SeaWaterReload": ("wols_ca/admin/command/SeaWaterReload", "mdi:reload"),
        "SeaWaterReset": ("wols_ca/admin/command/SeaWaterReset", "mdi:delete-alert")
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
        
        # Caching mechanism to prevent excessive disk I/O on SD cards
        self._cached_options = {}
        self._options_last_read = 0
        self._options_cache_ttl = 300  # Cache duration in seconds (5 minutes)

    def _get_options(self):
        """Helper to safely fetch options from disk with a 5-minute TTL cache."""
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

    def route_message(self, client, msg):
        topic = msg.topic
        try:
            payload = msg.payload.decode().strip()
        except UnicodeDecodeError:
            self.logger.error(f"Failed to decode payload for topic {topic}")
            return False

        # 1. Routing: Handshake & Security Lifecycle
        if topic in ["wols_ca/keys/public", "wols_ca/keys/raw_bytes", "wols_ca/admin/password_ack"]:
            self._handle_handshake(client, topic, payload, msg)
            return True

        # 2. Routing: Secrets Management (Pickup from HA UI)
        elif "/Admin/Secrets/" in topic:
            self._handle_secrets_pickup(client, topic, payload)
            return True
            
        # 3. Routing: Secrets Requests (From C++)
        elif topic.startswith("wols_ca/secrets/request/"):
            self._handle_secret_request(client, topic)
            return True

        # 4. Routing: Commands (Reload / Factory Reset)
        elif topic.startswith("wols_ca/admin/command/"):
            command = topic.split("/")[-1]
            
            if command == "SpotifyReload":
                self.logger.info("Manual reload requested for Spotify.")
                self._send_spotify_details(client)
                
            elif command == "SeaWaterReload":
                self.logger.info("Manual reload requested for Sea Water.")
                self._send_seawater_details(client)
                
            elif command == "SpotifyReset":
                self.logger.warning("FACTORY RESET TRIGGERED FOR SPOTIFY!")
                for i in range(1, 25):
                    for field in [f"SourceID{i}", f"TargetID{i}", f"PlayTime{i}"]:
                        secrets_handler.update_secret(field, "")
                        client.publish(f"wols_ca/admin/state/{field}", "", retain=True)
                # Send empty config to C++
                self._send_spotify_details(client, force_empty=True)

            elif command == "SeaWaterReset":
                self.logger.warning("FACTORY RESET TRIGGERED FOR SEA WATER!")
                for i in range(1, 101):
                    secrets_handler.update_secret(f"Position{i}", "")
                    client.publish(f"wols_ca/admin/state/Position{i}", "", retain=True)
                # Send empty config to C++
                self._send_seawater_details(client, force_empty=True)
            return True

        # 5. Routing: System & Version Control
        elif topic == "wols_ca/uploader/required_version":
            self._handle_version_check(payload)
            return True
            
        elif topic in [
            "wols_ca/uploader/version", 
            "wols_ca/uploader/status", 
            "wols_ca/admin/request_key", 
            "wols_ca/admin/encrypted_credentials"
        ]:
            return True

        return False

    def _handle_handshake(self, client, topic, payload, msg):
        if topic in ["wols_ca/keys/public", "wols_ca/keys/raw_bytes"]:
            global active_mqtt_user, active_mqtt_password
            public_key_handler.handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password)
            
        elif topic == "wols_ca/admin/password_ack":
            if payload == "ACK":
                self.logger.info("🚀 HANDSHAKE SUCCESS: Backend verified the credentials.")
                public_key_handler.promote_temp_key()
                client.subscribe([
                    ("wols_ca/trigger/#", 1),
                    ("spotify/+/Admin/Secrets/#", 1),
                    ("wols_ca/admin/command/#", 1),
                    ("wols_ca/admin/set_secret/#", 1)
                ])
                
                # PUSH: Send all configurations to C++ unconditionally
                self.logger.info("Pushing configuration to C++ Service...")
                self._send_ha_service_settings(client)
                self._send_spotify_details(client)
                self._send_seawater_details(client)

            elif payload == "NACK":
                self.logger.error("❌ Handshake REJECTED")
                public_key_handler.active_public_key = None
                public_key_handler.temp_public_key = None

    def _handle_secrets_pickup(self, client, topic, payload):
        if not payload:
            return 
        try:
            data = json.loads(payload)
            secret_value = data.get("current_value", "")
            if not secret_value or secret_value == "Stored by Uploader":
                return
                
            secret_name = topic.split("/")[-1]
            if secrets_handler.update_secret(secret_name, secret_value):
                feedback = json.dumps({
                    "current_value": "Stored by Uploader",
                    "purpose": data.get("purpose", ""),
                    "remark": "Secret securely moved."
                })
                client.publish(topic, feedback, qos=1, retain=True)
                
                if secret_name == "MQTTPassword":
                    global active_mqtt_password
                    active_mqtt_password = secret_value
                    client.publish("wols_ca/admin/request_key", "STARTUP_SYNC", qos=1)
        except json.JSONDecodeError:
            pass

    def _handle_secret_request(self, client, topic):
        request_type = topic.split("/")[-1] 
        if not public_key_handler.is_public_key_active():
            self.logger.warning(f"Request {request_type} Refused: No active RSA key.")
            return

        if request_type == "HAServiceSettings":
            self._send_ha_service_settings(client)
        elif request_type == "SpotifyDetails":
            self._send_spotify_details(client)
        elif request_type == "SeaWaterDetails":
            self._send_seawater_details(client)

    # --- PUSH FUNCTIONS ---
    def _send_ha_service_settings(self, client):
        options = self._get_options()
                
        data = {
            "BrokerURL": options.get("mqtt_broker", ""),
            "MqttUser": active_mqtt_user,
            "MqttPassword": active_mqtt_password,
            "ConsoleToMqtt": options.get("ConsoleToMqtt", False),
            "LogModus": options.get("LogModus", "INFO"),
            "RefreshMinutes": options.get("RefreshMinutes", 45),
            "TimeZone": options.get("TimeZone", "Europe/Amsterdam"),
            "ApiWhitelist": options.get("ApiWhitelist", "127.0.0.1")
        }
        self._send_config_response(client, "HAServiceSettings", data)

    def upload_to_cpp_service(self, client, new_config):
        global last_sent_config
        
        # Check if we can perform a 'quick' update
        is_token_refresh = False
        
        if last_sent_config:
            # Create a copy without the token to compare the rest
            current_data_no_token = {k: v for k, v in new_config.items() if k != 'access_token'}
            last_data_no_token = {k: v for k, v in last_sent_config.items() if k != 'access_token'}
            
            # If everything else is the same, but the token is different
            if current_data_no_token == last_data_no_token and new_config.get('access_token') != last_sent_config.get('access_token'):
                is_token_refresh = True

        # Add hint for the C++ service
        payload = new_config.copy()
        payload['AccessTokenOnly'] = is_token_refresh

        # Send the JSON to the C++ service (via MQTT or HTTP)
        self._send_config_response(client, "SpotifyDetails", payload)
        
        # Update the 'last' state
        last_sent_config = new_config

    def _send_spotify_details(self, client, force_empty=False):
        playlist_sets = []
        options = self._get_options()

        # 1. Read basic setting
        enabled = options.get("SpotifyEnabled", False)

        # 2. If the module is already disabled, abort immediately
        if not enabled or force_empty:
            data = {"Enabled": False}
            self.upload_to_cpp_service(client, data)
            return

        # 3. Collect the data
        max_sets = int(options.get("PlaylistSets", 0))
        for i in range(1, max_sets + 1):
            source = secrets_handler.get_secret(f"SourceID{i}")
            target = secrets_handler.get_secret(f"TargetID{i}")
            if not source or not target: break 
            
            playlist_sets.append({
                "source": source,
                "target": target,
                "play_time": secrets_handler.get_secret(f"PlayTime{i}")
            })
            
        # 4. EXTRA FAIL-SAFE: Is the list empty? Force 'Disabled'
        if not playlist_sets:
            self.logger.warning("Spotify is enabled, but no valid sets found. Forcing Disabled state.")
            data = {"Enabled": False}
            self.upload_to_cpp_service(client, data)
            return
        
        # 5. Everything is complete, send the full configuration
        data = {
            "Enabled": True,
            "Automate": options.get("SpotifyAutomate", False),
            "ClientID": secrets_handler.get_secret("SpotifyClientID"),
            "ClientSecret": secrets_handler.get_secret("ClientIDSecret"),
            "Sets": playlist_sets
        }
        self.upload_to_cpp_service(client, data)

    def _send_seawater_details(self, client, force_empty=False):
        positions = []
        options = self._get_options()

        # 1. Read basic setting
        enabled = options.get("SeaWaterEnabled", False)

        # 2. If the module is already disabled, abort immediately
        if not enabled or force_empty:
            data = {"Enabled": False}
            self._send_config_response(client, "SeaWaterDetails", data)
            return

        # 3. Collect the data
        interval = int(options.get("SensorInterval", 30))
        max_pos = int(options.get("SeaWaterNumber", 0))
        for i in range(1, max_pos + 1):
            pos = secrets_handler.get_secret(f"Position{i}")
            if not pos: break
            positions.append(pos)

        # 4. EXTRA FAIL-SAFE: Is the list empty? Force 'Disabled'
        if not positions:
            self.logger.warning("SeaWater is enabled, but no valid positions found. Forcing Disabled state.")
            data = {"Enabled": False}
            self._send_config_response(client, "SeaWaterDetails", data)
            return

        # 5. Everything is complete, send the full configuration
        data = {
            "Enabled": True,
            "SensorInterval": max(5, min(60, interval)),
            "Positions": positions
        }
        self._send_config_response(client, "SeaWaterDetails", data)

    def _send_config_response(self, client, key, data):
        options = self._get_options()
        
        # Retrieve the ID
        service_id = options.get("WolsCA_ServiceID", "").strip()
        
        # CHECK: Is the ID empty or not configured?
        if not service_id:
            self.logger.error("Error: WolsCA_ServiceID is not configured in the options!")
            return

        # If it's not empty, proceed
        base_prefix = "WolsCA/ServiceInstance"
        topic = f"{base_prefix}/{service_id}/Config/{key}"
        
        client.publish(topic, json.dumps(data), retain=True)

    def _handle_version_check(self, payload):
        """Processes incoming version information from the C++ service."""
        options = self._get_options()
        
        # 1. Retrieve the ServiceID for validation
        service_id = options.get("WolsCA_ServiceID", "").strip()
        
        # 2. Safety check: if we have no ID, abort
        if not service_id:
            self.logger.error("Version check aborted: WolsCA_ServiceID is empty.")
            return

        try:
            data = json.loads(payload)
            
            # 3. Check if the payload is intended for us (optional, but safe)
            incoming_id = data.get("service_id", "")
            if incoming_id and incoming_id != service_id:
                return # Message is for another instance, ignore it

            version = data.get("version", "Unknown")
            status = data.get("status", "Online")

            # 4. Log the status of the specific service host
            self.logger.info(f"WolsCA Service [{service_id}] is {status}. Version: {version}")
            
        except json.JSONDecodeError:
            self.logger.error("Version check: Received payload is not valid JSON.")

_router_instance = None
def handle_mqtt_message(client, msg, uploader_version):
    global _router_instance
    if _router_instance is None:
        _router_instance = MQTTMessageRouter(uploader_version)
    return _router_instance.route_message(client, msg)