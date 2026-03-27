import yaml

try:
    with open('wols_ca_uploader/config.yaml') as f:
        config_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    config_data = {}
f.close()

printString = "Version: " + str(config_data.get('version'));
print(printString)

with open('wols_ca_uploader/config/version.yaml', 'w') as f:
   f.write(printString)