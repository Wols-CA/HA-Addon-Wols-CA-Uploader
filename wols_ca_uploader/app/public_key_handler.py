import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from secrets_handler import get_secret  # You should have this function

def handle_public_key(client, msg):
    public_key_pem = msg.payload.decode()
    mqtt_password = get_secret("mqtt_password")  # Adjust key as needed

    # Load the public key
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Encrypt the password
    encrypted = public_key.encrypt(
        mqtt_password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    encrypted_b64 = base64.b64encode(encrypted).decode()

    # Publish the encrypted password to the correct topic
    client.publish("wols-ca/keys/encrypted_password", encrypted_b64)
