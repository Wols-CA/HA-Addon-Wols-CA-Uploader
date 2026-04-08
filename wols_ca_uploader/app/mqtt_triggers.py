import json
import logging
import threading
import os
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

active_mqtt_user = None
active_mqtt_password = None
# Bewaar de laatst verzonden config om te kunnen vergelijken
last_sent_config = {}

def set_mqtt_credentials(user, password):
    global active_mqtt_user, active_mqtt_password
    active_mqtt_user = user
    active_mqtt_password = password

# --- STANDALONE DASHBOARD DISCOVERY ---
def publish_dashboard_discovery(client):
    """Maakt automatisch invulvelden aan in Home Assistant via MQTT Discovery"""
    device_info = {
        "identifiers": ["wols_ca_vault"],
        "name": "Wols-CA Configuration Vault",
        "manufacturer": "Wols"
    }

    # Haal configuratie op 
    options_file = "/data/options.json"
    options = {}
    if os.path.exists(options_file):
        with open(options_file, "r") as f:
            options = json.load(f)

    spotify_sets = int(options.get("PlaylistSets", 0))
    seawater_num = int(options.get("SeaWaterNumber", 0))

    # 1. Maak de velden voor Spotify (max 24)
    for i in range(1, spotify_sets + 1):
        fields = {
            f"SourceID{i}": "mdi:spotify",
            f"TargetID{i}": "mdi:playlist-music",
            f"PlayTime{i}": "mdi:clock"
        }
        for secret_name, icon in fields.items():
            topic = f"homeassistant/text/wols_ca/{secret_name}/config"
            payload = {
                "name": f"Spotify {secret_name}",
                "unique_id": f"wols_ca_{secret_name}",
                "icon": icon,
                "command_topic": f"wols-ca/admin/set_secret/{secret_name}",
                "state_topic": f"wols-ca/admin/state/{secret_name}",
                "device": device_info
            }
            client.publish(topic, json.dumps(payload), retain=True)
            current_val = get_secret(secret_name) or ""
            client.publish(f"wols-ca/admin/state/{secret_name}", current_val, retain=True)

    # 2. Maak de velden voor SeaWater (max 100)
    for i in range(1, seawater_num + 1):
        secret_name = f"Position{i}"
        topic = f"homeassistant/text/wols_ca/{secret_name}/config"
        payload = {
            "name": f"SeaWater {secret_name}",
            "unique_id": f"wols_ca_{secret_name}",
            "icon": "mdi:map-marker",
            "command_topic": f"wols-ca/admin/set_secret/{secret_name}",
            "state_topic": f"wols-ca/admin/state/{secret_name}",
            "device": device_info
        }
        client.publish(topic, json.dumps(payload), retain=True)
        current_val = get_secret(secret_name) or ""
        client.publish(f"wols-ca/admin/state/{secret_name}", current_val, retain=True)

    # 3. Maak Reload en Factory Reset knoppen aan
    buttons = {
        "SpotifyReload": ("wols-ca/admin/command/SpotifyReload", "mdi:reload"),
        "SpotifyReset": ("wols-ca/admin/command/SpotifyReset", "mdi:delete-alert"),
        "SeaWaterReload": ("wols-ca/admin/command/SeaWaterReload", "mdi:reload"),
        "SeaWaterReset": ("wols-ca/admin/command/SeaWaterReset", "mdi:delete-alert")
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

        # 4. Routing: Dashboard Updates
        elif topic.startswith("wols-ca/admin/set_secret/"):
            secret_name = topic.split("/")[-1] 
            update_secret(secret_name, payload)
            logging.info(f"Secret bijgewerkt vanuit HA UI: {secret_name}")
            client.publish(f"wols-ca/admin/state/{secret_name}", payload, retain=True)
            return True   

        # 5. Routing: Commands (Reload / Factory Reset)
        elif topic.startswith("wols-ca/admin/command/"):
            command = topic.split("/")[-1]
            
            if command == "SpotifyReload":
                logging.info("Manual reload requested for Spotify.")
                self._send_spotify_details(client)
                
            elif command == "SeaWaterReload":
                logging.info("Manual reload requested for Sea Water.")
                self._send_seawater_details(client)
                
            elif command == "SpotifyReset":
                logging.warning("FACTORY RESET TRIGGERED FOR SPOTIFY!")
                for i in range(1, 25):
                    for field in [f"SourceID{i}", f"TargetID{i}", f"PlayTime{i}"]:
                        update_secret(field, "")
                        client.publish(f"wols-ca/admin/state/{field}", "", retain=True)
                # Stuur lege config naar C++
                self._send_spotify_details(client, force_empty=True)

            elif command == "SeaWaterReset":
                logging.warning("FACTORY RESET TRIGGERED FOR SEA WATER!")
                for i in range(1, 101):
                    update_secret(f"Position{i}", "")
                    client.publish(f"wols-ca/admin/state/Position{i}", "", retain=True)
                # Stuur lege config naar C++
                self._send_seawater_details(client, force_empty=True)
            return True

        # 6. Routing: System & Version Control
        elif topic == "wols-ca/uploader/required_version":
            self._handle_version_check(payload)
            return True
            
        elif topic in [
            "wols-ca/uploader/version", 
            "wols-ca/uploader/status", 
            "wols-ca/admin/request_key", 
            "wols-ca/admin/encrypted_credentials"
        ]:
            return True

        return False

    def _handle_handshake(self, client, topic, payload, msg):
        if topic in ["wols-ca/keys/public", "wols-ca/keys/raw_bytes"]:
            global active_mqtt_user, active_mqtt_password
            handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password)
            
        elif topic == "wols-ca/admin/password_ack":
            if payload == "ACK":
                logging.info("🚀 HANDSHAKE SUCCESS: Backend verified the credentials.")
                promote_temp_key()
                client.subscribe([
                    ("wols-ca/trigger/#", 1),
                    ("spotify/+/Admin/Secrets/#", 1),
                    ("wols-ca/admin/command/#", 1),
                    ("wols-ca/admin/set_secret/#", 1)
                ])
                
                # PUSH: Stuur direct alle configuraties ongevraagd naar C++
                logging.info("Pushing configuration to C++ Service...")
                self._send_ha_service_settings(client)
                self._send_spotify_details(client)
                self._send_seawater_details(client)

            elif payload == "NACK":
                logging.error("❌ Handshake REJECTED")
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
            if update_secret(secret_name, secret_value):
                feedback = json.dumps({
                    "current_value": "Stored by Uploader",
                    "purpose": data.get("purpose", ""),
                    "remark": "Secret securely moved."
                })
                client.publish(topic, feedback, qos=1, retain=True)
                
                if secret_name == "MQTTPassword":
                    global active_mqtt_password
                    active_mqtt_password = secret_value
                    client.publish("wols-ca/admin/request_key", "STARTUP_SYNC", qos=1)
        except json.JSONDecodeError:
            pass

    def _handle_secret_request(self, client, topic):
        request_type = topic.split("/")[-1] 
        if not is_public_key_active():
            logging.warning(f"Request {request_type} Refused: No active RSA key.")
            return

        if request_type == "HAServiceSettings":
            self._send_ha_service_settings(client)
        elif request_type == "SpotifyDetails":
            self._send_spotify_details(client)
        elif request_type == "SeaWaterDetails":
            self._send_seawater_details(client)

    # --- PUSH FUNCTIONS ---
    def _send_ha_service_settings(self, client):
        options_file = "/data/options.json"
        options = {}
        if os.path.exists(options_file):
            with open(options_file, "r") as f:
                options = json.load(f)
                
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

    def upload_to_cpp_service(self, client,new_config):
        global last_sent_config
        
        # Check of we een 'snelle' update kunnen doen
        is_token_refresh = False
        
        if last_sent_config:
            # Maak een kopie zonder de token om de rest te vergelijken
            current_data_no_token = {k: v for k, v in new_config.items() if k != 'access_token'}
            last_data_no_token = {k: v for k, v in last_sent_config.items() if k != 'access_token'}
            
            # Als de rest hetzelfde is, maar de token is anders
            if current_data_no_token == last_data_no_token and new_config.get('access_token') != last_sent_config.get('access_token'):
                is_token_refresh = True

        # Voeg de hint toe voor de C++ service
        payload = new_config.copy()
        if is_token_refresh:
            payload['AccessTokenOnly'] = True
        else:
            payload['AccessTokenOnly'] = False

        # Verstuur de JSON naar de C++ service (via MQTT of HTTP)
        self._send_config_response(client, "SpotifyDetails", payload)
        
        # Update de 'laatste' staat
        last_sent_config = new_config

    def _send_spotify_details(self, client, force_empty=False):
        playlist_sets = []
        enabled = False
        
        options_file = "/data/options.json"
        options = {}
        if os.path.exists(options_file):
            with open(options_file, "r") as f:
                options = json.load(f)

        if not force_empty:
            enabled = options.get("SpotifyEnabled", False)
            max_sets = int(options.get("PlaylistSets", 0))
            for i in range(1, max_sets + 1):
                source = get_secret(f"SourceID{i}")
                target = get_secret(f"TargetID{i}")
                if not source or not target: break 
                
                playlist_sets.append({
                    "source": source,
                    "target": target,
                    "play_time": get_secret(f"PlayTime{i}")
                })
        
        data = {
            "Enabled": enabled,
            "Automate": options.get("SpotifyAutomate", False),
            "ClientID": get_secret("SpotifyClientID") if not force_empty else "",
            "ClientSecret": get_secret("ClientIDSecret") if not force_empty else "",
            "Sets": playlist_sets
        }
        upload_to_cpp_service( client, data)
        

    def _send_seawater_details(self, client, force_empty=False):
        positions = []
        enabled = False
        interval = 30
        
        options_file = "/data/options.json"
        options = {}
        if os.path.exists(options_file):
            with open(options_file, "r") as f:
                options = json.load(f)

        if not force_empty:
            enabled = options.get("SeaWaterEnabled", False)
            interval = int(options.get("SensorInterval", 30))
            max_pos = int(options.get("SeaWaterNumber", 0))
            for i in range(1, max_pos + 1):
                pos = get_secret(f"Position{i}")
                if not pos: break
                positions.append(pos)

        data = {
            "Enabled": enabled,
            "SensorInterval": max(5, min(60, interval)),
            "Positions": positions
        }
        self._send_config_response(client, "SeaWaterDetails", data)

def _send_config_response(self, client, key, data):
    # Haal de ID op
    service_id = self.options.get("WolsCA_ServiceID", "").strip()
    
    # CHECK: Is de ID leeg of niet ingesteld?
    if not service_id:
        # We doen niets en loggen de fout
        self.logger.error("Error: WolsCA_ServiceID is not configured in the options!")
        return

    # Als het niet leeg is, gaan we verder
    base_prefix = "WolsCA/ServiceInstance"
    topic = f"{base_prefix}/{service_id}/Config/{key}"
    
    client.publish(topic, json.dumps(data), retain=True)
    # Log: "Config gepusht naar WolsCA Service op host: master-hub-woonkamer"

def _handle_version_check(self, payload):
    """
    Verwerkt inkomende versie-informatie van de C++ service.
    """
    # 1. Haal de ServiceID op om te valideren
    service_id = self.options.get("WolsCA_ServiceID", "").strip()
    
    # 2. Safety check: als we geen ID hebben, doen we niets
    if not service_id:
        self.logger.error("Versiecheck afgebroken: WolsCA_ServiceID is leeg.")
        return

    try:
        data = json.loads(payload)
        
        # 3. Check of de payload wel voor ons bedoeld is (optioneel, maar veilig)
        incoming_id = data.get("service_id", "")
        if incoming_id and incoming_id != service_id:
            return # Bericht is voor een andere instantie, negeer het

        version = data.get("version", "Onbekend")
        status = data.get("status", "Online")

        # 4. Log de status van de specifieke service-host
        self.logger.info(f"WolsCA Service [{service_id}] is {status}. Versie: {version}")
        
    except json.JSONDecodeError:
        self.logger.error("Versiecheck: Ontvangen payload is geen geldige JSON.")

_router_instance = None
def handle_mqtt_message(client, msg, uploader_version):
    global _router_instance
    if _router_instance is None:
        _router_instance = MQTTMessageRouter(uploader_version)
    return _router_instance.route_message(client, msg)