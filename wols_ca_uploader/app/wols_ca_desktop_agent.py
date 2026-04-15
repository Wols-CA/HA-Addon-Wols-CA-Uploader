import os
import time
import json
import logging
import paho.mqtt.client as mqtt

# ==============================================================================
# WOLS CA IT SECURITY NG - DESKTOP AGENT (PROVISIONING BRIDGE)
# ==============================================================================

# Configuration (Adjust to match your internal secure broker)
INTERNAL_BROKER_URL = "127.0.0.1" # The secure, internal side of the Hub
INTERNAL_BROKER_PORT = 1883
INTERNAL_USER = "admin_provisioning"
INTERNAL_PASS = "secure_internal_password"

TOPIC_REQUEST = "wols_ca_mqtt/admin/provision/request"
TOPIC_RESPONSE = "wols_ca_mqtt/admin/provision/response"

# Setup Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] WolsCA_DesktopAgent - %(message)s',
    datefmt='%Y-%m-%dT%H:%M:%S'
)
logger = logging.getLogger(__name__)

class ProvisioningAgent:
    def __init__(self):
        self.target_drive = None
        self.pending_cpu_id = None
        self.mqtt_client = mqtt.Client(client_id="WolsCA_Desktop_Provisioner")
        self.mqtt_client.username_pw_set(INTERNAL_USER, INTERNAL_PASS)
        self.mqtt_client.on_connect = self.on_connect
        self.mqtt_client.on_message = self.on_message

    def start(self):
        logger.info("Starting Wols CA Zero-Trust Desktop Agent...")
        try:
            self.mqtt_client.connect(INTERNAL_BROKER_URL, INTERNAL_BROKER_PORT, 60)
            self.mqtt_client.loop_start()
            self.run_usb_listener()
        except Exception as e:
            logger.error(f"Failed to connect to internal broker: {e}")
            logger.error("Ensure the internal Wols CA Hub is running.")

    def on_connect(self, client, userdata, flags, rc):
        if rc == 0:
            logger.info("Connected to internal Wols CA broker securely.")
            self.mqtt_client.subscribe(TOPIC_RESPONSE, qos=1)
        else:
            logger.error(f"Connection failed with code {rc}")

    def on_message(self, client, userdata, msg):
        if msg.topic == TOPIC_RESPONSE:
            self.handle_hub_response(msg.payload.decode('utf-8'))

    def find_provisioning_drive(self):
        """Scans Windows drives for the WOLS_PROV folder."""
        # Using A-Z drive letters for Windows compatibility
        drives = [f"{chr(x)}:\\" for x in range(65, 91) if os.path.exists(f"{chr(x)}:\\")]
        for drive in drives:
            prov_path = os.path.join(drive, "WOLS_PROV")
            if os.path.exists(prov_path):
                return prov_path
        return None

    def secure_shred_file(self, filepath):
        """Overwrites the file with zeros before deletion to prevent recovery."""
        try:
            length = os.path.getsize(filepath)
            with open(filepath, 'ba+', buffering=0) as f:
                f.seek(0)
                f.write(b'\x00' * length)
            os.remove(filepath)
            logger.info(f"Securely shredded: {os.path.basename(filepath)}")
        except Exception as e:
            logger.warning(f"Could not shred {filepath}: {e}")

    def handle_hub_response(self, payload_str):
        """Processes the encrypted onboarding package from the Manager."""
        if not self.target_drive:
            logger.warning("Received a response, but no USB drive is currently tracked.")
            return

        try:
            payload = json.loads(payload_str)
            
            # Verify the response matches the DNA we just sent
            response_cpu_id = payload.get("cpu_id")
            if response_cpu_id != self.pending_cpu_id:
                logger.warning(f"Mismatch! Response is for CPU {response_cpu_id}, but we requested {self.pending_cpu_id}.")
                return

            onboard_file = os.path.join(self.target_drive, "wols_ca_onboard.json")
            
            # Write the encrypted package to the USB
            with open(onboard_file, 'w') as f:
                json.dump(payload, f, indent=4)
                
            logger.info("Successfully wrote 'wols_ca_onboard.json' to USB.")
            logger.info("Phase 3 Complete. The USB can now be returned to the C++ Service Node.")
            
            # Reset state
            self.pending_cpu_id = None

        except json.JSONDecodeError:
            logger.error("Received malformed JSON from the Hub.")
        except Exception as e:
            logger.error(f"Error handling Hub response: {e}")

    def run_usb_listener(self):
        """Blocks and continuously monitors for the provisioning USB."""
        logger.info("Monitoring for WOLS_PROV USB drive...")
        
        while True:
            self.target_drive = self.find_provisioning_drive()
            
            if self.target_drive:
                dna_file = os.path.join(self.target_drive, "wols_dna.json")
                onboard_file = os.path.join(self.target_drive, "wols_ca_onboard.json")
                
                if os.path.exists(dna_file) and not os.path.exists(onboard_file):
                    logger.info("Detected new 'wols_dna.json'. Processing Phase 2...")
                    
                    try:
                        with open(dna_file, 'r') as f:
                            dna_content = json.load(f)
                            
                        # Store CPU ID to verify the incoming response later
                        self.pending_cpu_id = dna_content.get("hardware_dna", {}).get("cpu_id")
                        
                        # Forward to the Hub/Manager
                        self.mqtt_client.publish(TOPIC_REQUEST, json.dumps(dna_content), qos=1)
                        logger.info(f"DNA submitted to Manager for CPU: {self.pending_cpu_id}")
                        
                        # Execute "Burn 1" equivalent for the USB: destroy the raw DNA file
                        self.secure_shred_file(dna_file)
                        
                        logger.info("Waiting for Manager to generate cryptographic identity...")
                        
                    except Exception as e:
                        logger.error(f"Failed to read or process DNA file: {e}")
                        
            time.sleep(3)

if __name__ == "__main__":
    agent = ProvisioningAgent()
    agent.start()