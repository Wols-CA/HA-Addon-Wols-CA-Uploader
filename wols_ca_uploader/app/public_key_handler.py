import base64
import json
import logging
import secrets
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Service Keys (Ontvangen van C++)
active_public_key = None  
temp_public_key = None    
stored_credentials = {}

# Uploader Keys (Nieuw: Mutual RSA)
uploader_private_key = None
uploader_public_key_pem = None

def init_uploader_keys():
    """Genereert de asymmetrische Wols CA Uploader sleutels in het RAM."""
    global uploader_private_key, uploader_public_key_pem
    if uploader_private_key is None:
        logging.info("🔐 Wols CA: Genereren van eigen Uploader RSA-2048 sleutelpaar...")
        uploader_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        uploader_public_key_pem = uploader_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

def StepA_Process_PublicKey(client, msg, mqtt_user, mqtt_password, mqtt_url):
    """Fase 1: Ontvangt Public Key, genereert Ephemeral Kanaal & stuurt Uploader Public Key."""
    global temp_public_key, stored_credentials
    try:
        new_key = serialization.load_pem_public_key(msg.payload)
        if isinstance(new_key, rsa.RSAPublicKey):
            temp_public_key = new_key
            init_uploader_keys()
            
            safe_pass = mqtt_password if mqtt_password else ""
            from secrets_handler import get_secret
            product_key = get_secret("wols_ca_product_key")
            
            # WOLS CA FIX: Genereer het willekeurige sessie-kanaal (Burner Phone)
            ephemeral_session = f"wols_ca_mqtt/session/{secrets.token_hex(12)}"
            
            stored_credentials = {
                "url": mqtt_url, 
                "user": mqtt_user, 
                "pass": safe_pass, 
                "mailbox": product_key,
                "session_topic": ephemeral_session,
                "uploader_pub_key": uploader_public_key_pem
            }
            
            logging.info(f"🚀 [Step A] Service Public Key ontvangen. Genereren Ephemeral Channel: {ephemeral_session}")
            
            payload = json.dumps(stored_credentials)
            send_encrypted_payload(client, "wols_ca_mqtt/admin/encrypted_credentials", payload, use_temp=True)
    except Exception as e:
        logging.error(f"[Step A] Fout bij verwerken Service Public Key: {e}")

def StepC_Verify_Service_And_Respond(client, msg):
    """Fase 3: Controleert Signature en activeert Trace Wiping (Shadow Registry)."""
    global temp_public_key, active_public_key, stored_credentials
    try:
        envelope = json.loads(msg.payload.decode())
        data_str = envelope.get("data", "")
        incoming_signature = envelope.get("signature", "")
        
        secret_string = data_str + stored_credentials.get("pass", "")
        raw_hash = hashlib.sha256(secret_string.encode('utf-8'))
        
        expected_hex = raw_hash.hexdigest().lower()
        expected_b64 = base64.b64encode(raw_hash.digest()).decode('utf-8')
        
        if incoming_signature.lower() != expected_hex and incoming_signature != expected_b64:
            logging.error("[Step C] FATAL: Signature mismatch! Service identity compromised.")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            return

        data = json.loads(data_str)
        if (data.get("url") == stored_credentials["url"] and 
            data.get("user") == stored_credentials["user"]):
            
            # WOLS CA FIX: Haal de Raw ID ("SeaWater_01") op en update het Shadow Registry
            server_name = data.get("server_name", "Unknown_Service")
            session_topic = stored_credentials.get("session_topic")
            
            import mqtt_triggers
            mqtt_triggers.register_new_session(client, server_name, session_topic)
            
            logging.info(f"🚀 [Step C] Service '{server_name}' geverifieerd! Mutual RSA geactiveerd.")
            
            new_key_pem = data.get("new_pub_key")
            active_public_key = serialization.load_pem_public_key(new_key_pem.encode())
            temp_public_key = None
            
            verify_payload = json.dumps({"verify": "WolsCA_Uploader_Verified"})
            send_encrypted_payload(client, "wols_ca_mqtt/admin/uploader_verify", verify_payload)
        else:
            logging.error("[Step C] Credentials mismatch from service.")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            
    except Exception as e:
        logging.error(f"[Step C] Error verifying service: {e}")

def send_encrypted_payload(client, topic, plaintext, use_temp=False):
    key_to_use = temp_public_key if use_temp else active_public_key
    if not key_to_use: return
    encrypted = key_to_use.encrypt(
        plaintext.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    b64_string = base64.b64encode(encrypted).decode('utf-8')
    client.publish(topic, b64_string, qos=1, retain=False)

def decrypt_from_service(b64_encrypted_payload):
    """Nieuw: Ontsleutel inkomende berichten die versleuteld zijn met Uploader Public Key."""
    global uploader_private_key
    if not uploader_private_key: return None
    try:
        encrypted_bytes = base64.b64decode(b64_encrypted_payload)
        decrypted = uploader_private_key.decrypt(
            encrypted_bytes,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return decrypted.decode('utf-8')
    except Exception as e:
        logging.error(f"Fout bij Mutual RSA decryptie: {e}")
        return None

def handle_ack(payload):
    if payload == "ACK":
        logging.info("🚀 [Wols CA Handshake Complete] Mutual Authentication & Burner Channel Actief.")
    elif payload == "NACK":
        logging.error("❌ [Handshake Failed] Service rejected the verification.")

def update_rolling_key(new_pem_string):
    global active_public_key
    try:
        new_key = serialization.load_pem_public_key(new_pem_string.encode())
        if isinstance(new_key, rsa.RSAPublicKey):
            active_public_key = new_key
            logging.info("🚀 [Rolling Key] Security upgraded with new RSA generation.")
    except Exception as e:
        logging.error(f"Rolling Key update failed: {e}")