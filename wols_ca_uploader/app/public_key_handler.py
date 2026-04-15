import base64
import json
import logging
import secrets
import hashlib
import random
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

# ==============================================================================
# WOLS CA IT SECURITY NG - HONEYTOKEN STATE MACHINE
# ==============================================================================
# Tracks the expected behavioral NACK/ACK sequence for each connecting hardware ID.
active_handshakes = {}

# Service Keys
active_public_key = None  

# Uploader Keys
uploader_private_key = None
uploader_public_key_pem = None

def init_uploader_keys():
    global uploader_private_key, uploader_public_key_pem
    if uploader_private_key is None:
        logging.info("🔐 Wols CA: Generating internal Uploader RSA-2048 keypair...")
        uploader_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        uploader_public_key_pem = uploader_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

# --- RSA Block Chunking (Max 190 bytes plaintext per encryptie) ---
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

# ==============================================================================
# FASE 5: THE ZERO-TRUST HANDSHAKE
# ==============================================================================

def StepA_Process_Login_And_Challenge(client, msg, prod_url, prod_port, prod_user, prod_pass):
    """
    Receives the initial login from the C++ node, verifies the signature mathematically,
    and generates the Honeytoken (Fake Secrets) Challenge.
    """
    global active_handshakes
    try:
        payload = json.loads(msg.payload.decode('utf-8'))
        
        cpu_id = payload.get("cpu_id", "UNKNOWN")
        raw_pub_key = payload.get("pub_key", "").replace('\\n', '\n')
        the_secret = payload.get("secret", "")
        signature_b64 = payload.get("signature", "")
        
        # 1. Load the ephemeral Public Key sent by the Service
        spoke_pub_key = serialization.load_pem_public_key(raw_pub_key.encode('utf-8'))
        
        # 2. Verify Mathematical Signature
        try:
            signature_bytes = base64.b64decode(signature_b64)
            spoke_pub_key.verify(
                signature_bytes,
                the_secret.encode('utf-8'),
                padding.PKCS1v15(), # Standard C++ OpenSSL EVP_DigestSign uses PKCS1v15
                hashes.SHA256()
            )
            logging.info(f"✅ Signature mathematically verified for {cpu_id}. Preparing Honeytoken Challenge.")
        except InvalidSignature:
            logging.error(f"🚨 SECURITY ALERT: Invalid signature for {cpu_id}. Dropping connection.")
            return

        # 3. Generate Honeytokens (Fake Secrets to weed out Bots)
        num_fakes = random.randint(1, 3)
        challenges = []
        expected_sequence = []
        
        for _ in range(num_fakes):
            fake_secret = secrets.token_hex(16)
            enc_fake = encrypt_data_chunked(spoke_pub_key, fake_secret)
            challenges.append(base64.b64encode(enc_fake).decode('utf-8'))
            expected_sequence.append("NACK")
            
        # 4. Add the True Secret at the end
        enc_real = encrypt_data_chunked(spoke_pub_key, the_secret)
        challenges.append(base64.b64encode(enc_real).decode('utf-8'))
        
        # The expected ACK must contain the SHA-256 hash of the true secret
        expected_hash = hashlib.sha256(the_secret.encode('utf-8')).hexdigest()
        expected_sequence.append(f"ACK:{expected_hash}")
        
        # 5. Store State for Behavioral Analysis
        active_handshakes[cpu_id] = {
            "expected_sequence": expected_sequence,
            "current_index": 0,
            "pub_key": spoke_pub_key, 
            "prod_credentials": {
                "url": prod_url,
                "port": prod_port,
                "user": prod_user,
                "pass": prod_pass
            }
        }
        
        # 6. Send Challenges (Grouped in an array to guarantee MQTT arrival order)
        challenge_payload = json.dumps({"cpu_id": cpu_id, "challenges": challenges})
        client.publish("wols_ca_mqtt/admin/challenge", challenge_payload, qos=1)
        
    except Exception as e:
        logging.error(f"Error in Step A (Challenge Generation): {e}")

def StepB_Process_Response(client, msg):
    """
    Evaluates the incoming NACK/ACK sequence from the C++ Service.
    If the sequence is perfect, issues the production credentials.
    """
    global active_handshakes, active_public_key
    try:
        payload = json.loads(msg.payload.decode('utf-8'))
        cpu_id = payload.get("cpu_id")
        response = payload.get("response") # E.g., "NACK" or "ACK:<hash>"
        
        if cpu_id not in active_handshakes:
            return # Ignore orphaned responses
            
        state = active_handshakes[cpu_id]
        expected_response = state["expected_sequence"][state["current_index"]]
        
        # Evaluate Behavioral Logic
        if response != expected_response:
            logging.error(f"🚨 BOT DETECTED: Incorrect Honeytoken sequence from {cpu_id}. Disconnecting.")
            del active_handshakes[cpu_id]
            client.publish(f"wols_ca_mqtt/admin/production_credentials/{cpu_id}", "FAIL", qos=1)
            return
            
        state["current_index"] += 1
        
        # Check if the full challenge sequence is complete
        if state["current_index"] == len(state["expected_sequence"]):
            logging.info(f"🚀 Honeytoken Challenge PASSED for {cpu_id}! Handing over Production Credentials.")
            
            prod_creds = state["prod_credentials"]
            spoke_pub_key = state["pub_key"]
            
            # Encrypt the final production credentials (The Crown Jewels)
            final_payload = json.dumps(prod_creds)
            enc_final = encrypt_data_chunked(spoke_pub_key, final_payload)
            b64_final = base64.b64encode(enc_final).decode('utf-8')
            
            # Send them and promote the ephemeral key to active production key
            client.publish(f"wols_ca_mqtt/admin/production_credentials/{cpu_id}", b64_final, qos=1)
            active_public_key = spoke_pub_key
            del active_handshakes[cpu_id]
            
    except Exception as e:
        logging.error(f"Error in Step B (Response Evaluation): {e}")

# --- Helper functions for post-handshake operational phase ---

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
    if not active_public_key: raise ValueError("No active key")
    encrypted = encrypt_data_chunked(active_public_key, plaintext)
    return base64.b64encode(encrypted).decode('utf-8')