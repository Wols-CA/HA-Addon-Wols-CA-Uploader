import paho.mqtt.client as mqtt
import logging

def sanitize_mqtt_broker_url(raw_broker, port):
    """Zorgt voor een schoon IP en een standaard URL, ongeacht wat de gebruiker intypt."""
    if "//" in str(raw_broker): clean_broker = str(raw_broker).split("//")[-1]
    else: clean_broker = str(raw_broker)
    clean_broker = clean_broker.split("/")[0]
    if ":" in clean_broker: clean_broker = clean_broker.split(":")[0]
    return clean_broker, f"mqtt://{clean_broker}:{port}"

class MQTTBaseClient:
    """De generieke MQTT basisklasse voor Wols CA (Niet specifiek voor Intern/Extern)"""
    def __init__(self, client_id, broker_ip, port, user, password):
        self.logger = logging.getLogger(client_id)
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=client_id)
        
        if user and password:
            self.client.username_pw_set(user, password)
            
        self.broker_ip = broker_ip
        self.port = port
        
        # Koppel de standaard callbacks
        self.client.on_connect = self._on_connect_wrapper
        self.client.on_message = self.on_message

    def _on_connect_wrapper(self, client, userdata, flags, reason_code, properties=None):
        if reason_code == 0:
            self.logger.info(f"✅ Connected successfully to {self.broker_ip}:{self.port}")
            self.on_successful_connect()
        else:
            self.logger.error(f"❌ Connection failed with code {reason_code}")

    def connect_and_start(self):
        self.logger.info(f"Initiating connection to {self.broker_ip}:{self.port}...")
        self.client.connect(self.broker_ip, self.port, 60)
        self.client.loop_start() # Draait non-blocking op de achtergrond

    def publish(self, topic, payload, retain=False):
        """Generieke publicatie, al het specifieke gaat via de parameters."""
        self.client.publish(topic, payload, retain=retain)

    # Deze methodes moeten overschreven worden door de kind-klassen (Int/Ext)
    def on_successful_connect(self): pass
    def on_message(self, client, userdata, msg): pass