import yaml
import logging

SECRETS_FILE = "/config/secrets.yaml"  # Adjust path for your HA setup

def get_secret(name):
    try:
        with open(SECRETS_FILE, "r") as f:
            secrets = yaml.safe_load(f)
        return secrets.get(name)
    except Exception as e:
        logging.info(f"Error reading secret {name}: {e}")
        return None

def update_secret(name, value):
    try:
        with open(SECRETS_FILE, "r") as f:
            secrets = yaml.safe_load(f)
        secrets[name] = value
        with open(SECRETS_FILE, "w") as f:
            yaml.safe_dump(secrets, f)
        return True
    except Exception as e:
        logging.info(f"Error updating secret {name}: {e}")
        return False
