import json
from mqtt_util import MQTTBaseClient

class MQTTInternalBridge(MQTTBaseClient):
    def __init__(self, client_id, broker_ip, port, user, password, product_key):
        super().__init__(client_id, broker_ip, port, user, password)
        self.product_key = product_key

    def on_successful_connect(self):
        self.logger.info("🛡️ INTERNAL: Safe Zone ready. Publishing HA Discovery...")
        self._publish_discovery()

    def _publish_discovery(self):
        """Publiceert de apparaat-structuur naar HA"""
        dev_seawater = {
            "identifiers": [f"wols_ca_{self.product_key}_sw_system"], 
            "name": "Wols CA SeaWater System", 
            "manufacturer": "Wols CA", 
            "model": "NG Security Bridge"
        }
        
        for i in range(1, 101):
            # Sensor voor Temperatuurweergave
            sensor_payload = {
                "name": f"Sea Temperature {i}",
                "unique_id": f"wols_ca_sw_temp_{i}",
                "state_topic": f"wols_ca/sensor/sw_temp_{i}/state",
                "unit_of_measurement": "°C",
                "device_class": "temperature",
                "value_template": "{{ value_json.temp }}",
                "device": dev_seawater,
                "icon": "mdi:thermometer-water"
            }
            self.publish(f"homeassistant/sensor/wols_ca/sw_temp_{i}/config", json.dumps(sensor_payload), retain=True)

    def publish_seawater_data(self, pos_num, temperature):
        """Wordt aangeroepen door de dirigent zodra er schone data is."""
        state_topic = f"wols_ca/sensor/sw_temp_{pos_num}/state"
        self.publish(state_topic, json.dumps({"temp": temperature}), retain=True)
        self.logger.info(f"🛡️ INTERNAL: Published clean data to HA for Position {pos_num}")