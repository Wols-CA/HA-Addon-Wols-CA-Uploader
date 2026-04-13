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
            
            safe_pass = mqtt_password if mqtt_password else ""
            
            # WOLS CA FIX: Haal de Product Key op en verstop hem in de versleutelde Handshake!
            from secrets_handler import get_secret
            product_key = get_secret("wols_ca_product_key")
            
            stored_credentials = {"url": mqtt_url, "user": mqtt_user, "pass": safe_pass, "mailbox": product_key}
            
            logging.info("🚀 [Step A] RSA Public Key received. Sending encrypted credentials & Product Key (Step B)...")
            
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
        
        # 1. Bepaal de ruwe SHA256 Hash
        secret_string = data_str + stored_credentials.get("pass", "")
        raw_hash = hashlib.sha256(secret_string.encode('utf-8'))
        
        # 2. Bepaal de verwachte antwoorden (Kleine letters hex, OF Base64)
        expected_hex = raw_hash.hexdigest().lower()
        expected_b64 = base64.b64encode(raw_hash.digest()).decode('utf-8')
        
        incoming_sig_lower = incoming_signature.lower()
        
        # 3. Wols CA Robuuste Verificatie
        if incoming_sig_lower != expected_hex and incoming_signature != expected_b64:
            logging.error("[Step C] FATAL: Signature mismatch! Service identity compromised.")
            logging.error(f"   -> C++ Sent       : {incoming_signature}")
            logging.error(f"   -> Python Expects : {expected_hex} (Hex) OR {expected_b64} (Base64)")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            return

        # 4. Als de controle slaagt, ontsleutel de rest
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
        plaintext.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_string = base64.b64encode(encrypted).decode('utf-8')
    client.publish(topic, b64_string, qos=1, retain=False)
    
def handle_ack(payload):
    if payload == "ACK":
        logging.info("🚀 [Wols CA Handshake Complete] Mutual Authentication Successful. System Operational.")
    elif payload == "NACK":
        logging.error("❌ [Handshake Failed] Service rejected the verification.")

def promote_temp_key():
    pass # Replaced dynamically during Step C

def is_public_key_active():
    return active_public_key is not None

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