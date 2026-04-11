import base64
import json
import logging
import secrets
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# Global key states - De "Handshake Memory"
active_public_key = None  # De vertrouwde sleutel voor productie
temp_public_key = None    # De sleutel in afwachting van password_ack

def get_scrambled_path(mailbox_id, sub_topic):
    """Berekent het troebele pad conform de Wols CA standaard."""
    mb_hash = hashlib.sha256(mailbox_id.encode()).hexdigest()[:16]
    sub_hash = hashlib.sha256(sub_topic.encode()).hexdigest()[:16]
    return f"wols_ca_mqtt/mb/{mb_hash}/{sub_hash}"

def handle_raw_bytes(client, msg, active_mqtt_user, active_mqtt_password):
    """Verwerkt de initiële RSA Public Key levering (Trap 1)."""
    global temp_public_key, active_public_key 
    
    try:
        pem_data = msg.payload
        new_key = serialization.load_pem_public_key(pem_data)
        
        if isinstance(new_key, rsa.RSAPublicKey):
            # Bij een nieuwe initiële sleutel wissen we de oude status
            active_public_key = None 
            temp_public_key = new_key
            logging.info("🚀 Trap 1: RSA Key geladen. Start verificatie...")
            
            if active_mqtt_user and active_mqtt_password:
                credentials = {"user_id": active_mqtt_user, "password": active_mqtt_password}
                # Handshake paden blijven tijdelijk op de vaste admin topics
                send_encrypted_payload(client, "wols_ca_mqtt/admin/encrypted_credentials", json.dumps(credentials))
            else:
                logging.error("Handshake afgebroken: Geen MQTT credentials beschikbaar.")
    except Exception as e:
        logging.error(f"Fout bij verwerken publieke sleutel: {e}")

def handle_rolling_key(payload):
    """Verwerkt een 'Rolling Key' update (Trap 2 & 3)."""
    global active_public_key
    try:
        # De payload is een 'e-mail' envelop van de service
        envelope = json.loads(payload)
        if envelope.get("header", {}).get("type") == "KEY_ROTATION":
            new_pem = envelope.get("payload", "").encode()
            new_key = serialization.load_pem_public_key(new_pem)
            
            # De keten van vertrouwen: De nieuwe sleutel vervangt de oude
            active_public_key = new_key
            logging.info("🚀 Rolling Key Succes: Systeem beveiligd met nieuwe generatie sleutels.")
            return True
    except Exception as e:
        logging.error(f"Rolling Key verificatie mislukt: {e}")
    return False

def encrypted_text(plaintext):
    """Versleutelt tekst met de actieve of tijdelijke sleutel."""
    key_to_use = active_public_key or temp_public_key
    if not key_to_use:
        return base64.b64encode(secrets.token_bytes(256)).decode()

    encrypted = key_to_use.encrypt(
        plaintext.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode()

def send_encrypted_payload(client, topic, plaintext):
    """Verpakt en verstuurt een versleuteld bericht."""
    try:
        b64_string = encrypted_text(plaintext)
        # Gebruik retain=False voor alle reguliere communicatie
        client.publish(topic, b64_string, qos=1, retain=False)
    except Exception as e:
        logging.error(f"Publicatie van versleuteld bericht mislukt op {topic}: {e}")

def promote_temp_key():
    """Promoveert de tijdelijke sleutel naar ACTIEF na succesvolle handshake."""
    global active_public_key, temp_public_key
    if temp_public_key:
        active_public_key = temp_public_key
        logging.info("🚀 Handshake voltooid: Sleutel is nu ACTIEF.")
    else:
        logging.error("Promotie mislukt: Geen tijdelijke sleutel aanwezig.")

def is_public_key_active():
    return active_public_key is not None