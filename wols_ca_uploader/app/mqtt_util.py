import paho.mqtt.client as mqtt
import logging
import time

def sanitize_mqtt_broker_url(raw_broker, port):
    if "//" in str(raw_broker): clean_broker = str(raw_broker).split("//")[-1]
    else: clean_broker = str(raw_broker)
    clean_broker = clean_broker.split("/")[0]
    if ":" in clean_broker: clean_broker = clean_broker.split(":")[0]
    return clean_broker, f"mqtt://{clean_broker}:{port}"

class MQTTBaseClient:
    def __init__(self, client_id, broker_ip, port, user, password):
        self.bridge_name = "INTERNAL (Safe Zone)" if "Int" in client_id else "EXTERNAL (DMZ)"
        self.logger = logging.getLogger("WolsCA")
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        
        self.user = user
        self.password = password
        if user and password:
            self.client.username_pw_set(user, password)
            
        self.broker_ip = broker_ip
        self.port = port
        self.auth_failed = False # Vlag voor autorisatiefouten
        
        self.client.on_connect = self._on_connect_wrapper
        self.client.on_message = self.on_message

    def _on_connect_wrapper(self, client, userdata, flags, reason_code, properties=None):
        # reason_code 5 = Connection Refused: not authorised (v3.1.1)
        # In v5 zijn er meerdere codes voor unauthorized.
        if reason_code == 0:
            self.logger.info(f"✅ [{self.bridge_name}] Connected successfully to {self.broker_ip}:{self.port}")
            self.auth_failed = False
            self.on_successful_connect()
        elif reason_code in [5, 134, 135]: # Unauthorized codes
            self.logger.error(f"❌ [{self.bridge_name}] Not authorized (code {reason_code}). Entering 5-minute cooldown.")
            self.auth_failed = True
            self.stop() # Stop direct met proberen
        else:
            self.logger.error(f"⚠️ [{self.bridge_name}] Connection failed (code {reason_code}). Retrying...")

    def update_credentials(self, user, password):
        """Update inloggegevens voor de volgende poging"""
        self.user = user
        self.password = password
        if user and password:
            self.client.username_pw_set(user, password)
        self.auth_failed = False

    def connect_and_start(self):
        if self.auth_failed:
            return
        try:
            self.client.connect_async(self.broker_ip, self.port, 60)
            self.client.loop_start()
        except Exception as e:
            self.logger.error(f"[{self.bridge_name}] Socket error: {e}")

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

    def publish(self, topic, payload, retain=False):
        self.client.publish(topic, payload, retain=retain)

    def on_successful_connect(self): pass
    def on_message(self, client, userdata, msg): pass