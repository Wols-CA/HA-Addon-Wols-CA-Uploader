import base64
import json
import logging
import secrets
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

active_public_key = None  
temp_public_key = None    
stored_credentials = {}

def StepA_Process_PublicKey(client, msg, mqtt_user, mqtt_password, mqtt_url):
    """
    Wols CA Step A: Receives Public Key A, encrypts credentials, and sends Step B.
    """
    global temp_public_key, stored_credentials
    try:
        new_key = serialization.load_pem_public_key(msg.payload)
        if isinstance(new_key, rsa.RSAPublicKey):
            temp_public_key = new_key
            
            # Store for verification in Step C
            stored_credentials = {"url": mqtt_url, "user": mqtt_user, "pass": mqtt_password}
            logging.info("🚀 [Step A] RSA Public Key received. Sending encrypted credentials (Step B)...")
            
            payload = json.dumps(stored_credentials)
            send_encrypted_payload(client, "wols_ca_mqtt/admin/encrypted_credentials", payload, use_temp=True)
    except Exception as e:
        logging.error(f"[Step A] Error processing public key: {e}")

def StepC_Verify_Service_And_Respond(client, msg):
    """
    Wols CA Step C: Verifies the Service's signature, promotes Key B, and sends final Uploader Verify.
    """
    global temp_public_key, active_public_key, stored_credentials
    try:
        envelope = json.loads(msg.payload.decode())
        data_str = envelope.get("data", "")
        incoming_signature = envelope.get("signature", "")
        
        # Verify the signature using the password as Proof of Decryption
        expected_sig = hashlib.sha256((data_str + stored_credentials.get("pass", "")).encode()).hexdigest()
        
        if incoming_signature != expected_sig:
            logging.error("[Step C] FATAL: Signature mismatch! Service identity compromised.")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            return

        data = json.loads(data_str)
        if (data.get("url") == stored_credentials["url"] and 
            data.get("user") == stored_credentials["user"] and 
            data.get("pass") == stored_credentials["pass"]):
            
            logging.info("🚀 [Step C] Service identity verified! Promoting New Key B.")
            
            new_key_pem = data.get("new_pub_key")
            active_public_key = serialization.load_pem_public_key(new_key_pem.encode())
            temp_public_key = None
            
            # Encrypt a known verification string with the NEW public key
            verify_payload = json.dumps({"verify": "WolsCA_Uploader_Verified"})
            send_encrypted_payload(client, "wols_ca_mqtt/admin/uploader_verify", verify_payload)
        else:
            logging.error("[Step C] Credentials mismatch from service.")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            
    except Exception as e:
        logging.error(f"[Step C] Error verifying service: {e}")

def send_encrypted_payload(client, topic, plaintext, use_temp=False):
    """Encrypts and publishes data securely."""
    key_to_use = temp_public_key if use_temp else active_public_key
    if not key_to_use:
        return
        
    encrypted = key_to_use.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_string = base64.b64encode(encrypted).decode()
    client.publish(topic, b64_string, qos=1, retain=False)
    
def handle_ack(payload):
    if payload == "ACK":
        logging.info("🚀 [Wols CA Handshake Complete] Mutual Authentication Successful. System Operational.")
    elif payload == "NACK":
        logging.error("❌ [Handshake Failed] Service rejected the verification.")

def update_rolling_key(new_pem_string):
    """Processes Jitter/Rolling Key updates."""
    global active_public_key
    try:
        new_key = serialization.load_pem_public_key(new_pem_string.encode())
        if isinstance(new_key, rsa.RSAPublicKey):
            active_public_key = new_key
            logging.info("🚀 [Rolling Key] Security upgraded with new RSA generation.")
    except Exception as e:
        logging.error(f"Rolling Key update failed: {e}")