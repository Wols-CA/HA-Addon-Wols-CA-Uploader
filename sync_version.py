import yaml

# Copy version from config/version.yaml to config.yaml
with open('config/version.yaml') as f:
    version_data = yaml.safe_load(f) or {}

try:
    with open('wols_ca_uploader/config.yaml') as f:
        config_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    config_data = {}

if 'version' in config_data:
    version_data['version'] = config_data['version']
else:
    print("Warning: 'version' not found in wols_ca_uploader/config.yaml")

with open('config/version.yaml', 'w') as f:
    yaml.safe_dump(version_data, f)