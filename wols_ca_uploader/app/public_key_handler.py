import base64
import json
import logging
import secrets
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --- WOLS CA VERSIE CONTROLE ---
UPLOADER_MIN_ACCEPTED_SERVICE = "0.5.0"
UPLOADER_MAX_ACCEPTED_SERVICE = "2.9.9"

def is_version_allowed(version, min_v, max_v):
    def parse_v(v): return tuple(map(int, str(v).split('.')))
    try: return parse_v(min_v) <= parse_v(version) <= parse_v(max_v)
    except Exception: return False

# Service Keys
active_public_key = None  
temp_public_key = None    
stored_credentials = {}

# Uploader Keys
uploader_private_key = None
uploader_public_key_pem = None

def init_uploader_keys():
    global uploader_private_key, uploader_public_key_pem
    if uploader_private_key is None:
        logging.info("🔐 Wols CA: Genereren van eigen Uploader RSA-2048 sleutelpaar...")
        uploader_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        uploader_public_key_pem = uploader_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

# --- WOLS CA FIX: RSA Block Chunking (Max 190 bytes plaintext per encryptie) ---
def encrypt_data_chunked(public_key, plaintext):
    plaintext_bytes = plaintext.encode('utf-8')
    chunk_size = 190
    encrypted_bytes = bytearray()
    for i in range(0, len(plaintext_bytes), chunk_size):
        chunk = plaintext_bytes[i:i+chunk_size]
        encrypted_chunk = public_key.encrypt(
            chunk,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        encrypted_bytes.extend(encrypted_chunk)
    return bytes(encrypted_bytes)

def decrypt_data_chunked(private_key, encrypted_bytes):
    chunk_size = 256
    decrypted_bytes = bytearray()
    for i in range(0, len(encrypted_bytes), chunk_size):
        chunk = encrypted_bytes[i:i+chunk_size]
        if len(chunk) != chunk_size: break
        decrypted_chunk = private_key.decrypt(
            chunk,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        decrypted_bytes.extend(decrypted_chunk)
    return decrypted_bytes.decode('utf-8')
# ---------------------------------------------------------------------------------

def StepA_Process_PublicKey(client, msg, mqtt_user, mqtt_password, mqtt_url, current_uploader_version):
    global temp_public_key, stored_credentials
    try:
        payload_data = json.loads(msg.payload.decode('utf-8'))
        raw_pub_key = payload_data.get("pub_key", "")
        if isinstance(raw_pub_key, str):
            raw_pub_key = raw_pub_key.replace('\\n', '\n').replace('\\r', '')

        service_version = payload_data.get("service_version", "0.0.0")
        req_min_uploader = payload_data.get("min_uploader", "0.0.0")
        req_max_uploader = payload_data.get("max_uploader", "99.99.99")

        if not is_version_allowed(service_version, UPLOADER_MIN_ACCEPTED_SERVICE, UPLOADER_MAX_ACCEPTED_SERVICE):
            logging.error(f"❌ [Versie Controle] Service versie {service_version} is afgewezen.")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            return

        if not is_version_allowed(current_uploader_version, req_min_uploader, req_max_uploader):
            logging.error(f"❌ [Versie Controle] Uploader v{current_uploader_version} is buiten de C++ eisen. Afgewezen.")
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            return

        new_key = serialization.load_pem_public_key(raw_pub_key.encode('utf-8'))
        if isinstance(new_key, rsa.RSAPublicKey):
            temp_public_key = new_key
            init_uploader_keys()
            
            safe_pass = mqtt_password if mqtt_password else ""
            from secrets_handler import get_secret
            product_key = get_secret("wols_ca_product_key")
            
            ephemeral_session = f"wols_ca_mqtt/session/{secrets.token_hex(12)}"
            
            stored_credentials = {
                "url": mqtt_url, "user": mqtt_user, "pass": safe_pass, 
                "mailbox": product_key, "session_topic": ephemeral_session,
                "uploader_pub_key": uploader_public_key_pem, "uploader_version": current_uploader_version
            }
            
            logging.info(f"🚀 [Step A] Genereren Ephemeral Channel: {ephemeral_session}")
            payload = json.dumps(stored_credentials)
            send_encrypted_payload(client, "wols_ca_mqtt/admin/encrypted_credentials", payload, use_temp=True)
            
    except Exception as e: logging.error(f"[Step A] Fout bij verwerken Service Public Key: {e}")

def StepC_Verify_Service_And_Respond(client, msg):
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
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            return

        data = json.loads(data_str)
        if (data.get("url") == stored_credentials["url"] and data.get("user") == stored_credentials["user"]):
            
            server_name = data.get("server_name", "Unknown_Service")
            session_topic = stored_credentials.get("session_topic")
            
            import mqtt_triggers
            mqtt_triggers.register_new_session(client, server_name, session_topic)
            logging.info(f"🚀 [Step C] Service '{server_name}' geverifieerd! Mutual RSA geactiveerd.")
            
            new_key_pem = data.get("new_pub_key")
            if isinstance(new_key_pem, str):
                new_key_pem = new_key_pem.replace('\\n', '\n').replace('\\r', '')

            active_public_key = serialization.load_pem_public_key(new_key_pem.encode())
            temp_public_key = None
            
            verify_payload = json.dumps({"verify": "WolsCA_Uploader_Verified"})
            send_encrypted_payload(client, "wols_ca_mqtt/admin/uploader_verify", verify_payload)
        else:
            client.publish("wols_ca_mqtt/admin/password_ack", "NACK", qos=1, retain=False)
            
    except Exception as e: logging.error(f"[Step C] Error verifying service: {e}")

def send_encrypted_payload(client, topic, plaintext, use_temp=False):
    key_to_use = temp_public_key if use_temp else active_public_key
    if not key_to_use: return
    encrypted = encrypt_data_chunked(key_to_use, plaintext)
    b64_string = base64.b64encode(encrypted).decode('utf-8')
    client.publish(topic, b64_string, qos=1, retain=False)

def decrypt_from_service(b64_encrypted_payload):
    global uploader_private_key
    if not uploader_private_key: return None
    try:
        encrypted_bytes = base64.b64decode(b64_encrypted_payload)
        return decrypt_data_chunked(uploader_private_key, encrypted_bytes)
    except Exception as e:
        logging.error(f"Fout bij Mutual RSA decryptie: {e}")
        return None

def bulk_encrypt_for_service(plaintext):
    """Helper voor mqtt_triggers om grote data te versleutelen."""
    if not active_public_key: raise ValueError("No active key")
    encrypted = encrypt_data_chunked(active_public_key, plaintext)
    return base64.b64encode(encrypted).decode('utf-8')

def handle_ack(payload):
    if payload == "ACK": logging.info("🚀 [Wols CA Handshake Complete] Mutual Authentication & Burner Channel Actief.")
    elif payload == "NACK": logging.error("❌ [Handshake Failed] Service rejected the verification.")

def update_rolling_key(new_pem_string):
    global active_public_key
    try:
        if isinstance(new_pem_string, str): new_pem_string = new_pem_string.replace('\\n', '\n').replace('\\r', '')
        new_key = serialization.load_pem_public_key(new_pem_string.encode())
        if isinstance(new_key, rsa.RSAPublicKey):
            active_public_key = new_key
            logging.info("🚀 [Rolling Key] Security upgraded with new RSA generation.")
    except Exception as e: logging.error(f"Rolling Key update failed: {e}")