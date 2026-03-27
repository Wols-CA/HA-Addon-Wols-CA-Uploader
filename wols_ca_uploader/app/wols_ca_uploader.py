import paho.mqtt.client as mqtt
import os
import yaml

from mqtt_triggers import handle_mqtt_message

def get_version_from_yaml():
    version_file = "/config/version.yaml"
    with open(version_file, "r") as f:
        data = yaml.safe_load(f)
    return data.get("version", "0.0.0")

UPLOADER_VERSION = get_version_from_yaml()
MQTT_BROKER = "localhost"  # Change as needed
MQTT_PORT = 1883

def on_connect(client, userdata, flags, rc):
    print("Connected with result code", rc)
    # Subscribe to all relevant topics for triggers, handshake, secrets, etc.
    client.subscribe("wols-ca/trigger/#")
    client.subscribe("wols-ca/keys/public")
    client.subscribe("wols-ca/secrets/request/#")
    client.subscribe("wols-ca/uploader/required_version")
    # Add more as needed
    
    # After connecting to MQTT:
    publish_version(client, UPLOADER_VERSION)

def on_message(client, userdata, msg):
    if not handle_mqtt_message(client, msg, UPLOADER_VERSION):
        print(f"No handler for topic: {msg.topic}")

def publish_version(client, version):
    client.publish("wols-ca/uploader/version", version, retain=True)

def main():
    client = mqtt.Client()
    client.on_connect = on_connect
    client.on_message = on_message
    client.connect(MQTT_BROKER, MQTT_PORT, 60)
    publish_version(client)
    client.loop_forever()

if __name__ == "__main__":
    main()
