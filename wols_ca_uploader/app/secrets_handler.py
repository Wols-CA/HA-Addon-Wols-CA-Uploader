import yaml
import logging
import os

SECRETS_FILE = "/config/secrets.yaml"

def get_secret(name):
    if not os.path.exists(SECRETS_FILE):
        return None
    try:
        with open(SECRETS_FILE, "r") as f:
            secrets_data = yaml.safe_load(f) or {}
        return secrets_data.get(name)
    except Exception as e:
        logging.error(f"Fout bij lezen secret '{name}': {e}")
        return None

def update_secret(name, value):
    try:
        secrets_data = {}
        if os.path.exists(SECRETS_FILE):
            with open(SECRETS_FILE, "r") as f:
                secrets_data = yaml.safe_load(f) or {}

        if secrets_data.get(name) == value:
            return True

        secrets_data[name] = value
        with open(SECRETS_FILE, "w") as f:
            yaml.safe_dump(secrets_data, f, default_flow_style=False)
        
        logging.info(f"Secret bijgewerkt: {name}")
        return True
    except Exception as e:
        logging.error(f"Fout bij bijwerken secret '{name}': {e}")
        return False