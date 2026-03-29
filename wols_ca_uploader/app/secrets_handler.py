import yaml
import logging
import os

# Standard path for Home Assistant configuration
SECRETS_FILE = "/config/secrets.yaml"

def get_secret(name):
    """Retrieves a secret from the HA secrets.yaml file."""
    if not os.path.exists(SECRETS_FILE):
        logging.error(f"Secrets file not found at {SECRETS_FILE}")
        return None

    try:
        with open(SECRETS_FILE, "r") as f:
            secrets = yaml.safe_load(f) or {} # Handle empty files
        return secrets.get(name)
    except Exception as e:
        logging.error(f"Error reading secret '{name}': {e}")
        return None

def update_secret(name, value):
    """Updates or adds a secret to the HA secrets.yaml file."""
    try:
        secrets = {}
        if os.path.exists(SECRETS_FILE):
            with open(SECRETS_FILE, "r") as f:
                secrets = yaml.safe_load(f) or {}

        secrets[name] = value
        
        with open(SECRETS_FILE, "w") as f:
            yaml.safe_dump(secrets, f, default_flow_style=False)
        
        logging.info(f"Successfully updated secret: {name}")
        return True
    except Exception as e:
        logging.error(f"Error updating secret '{name}': {e}")
        return False