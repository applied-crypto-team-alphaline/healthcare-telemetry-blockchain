import json
import os
import time


REGISTRY_FILE = "device_registry.json"


class DeviceRegistry:
    def __init__(self, registry_file=REGISTRY_FILE):
        self.registry_file = registry_file
        if not os.path.exists(self.registry_file):
            with open(self.registry_file, "w", encoding="utf-8") as f:
                json.dump({}, f)

    def _load(self):
        with open(self.registry_file, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save(self, data):
        with open(self.registry_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def register_device(self, device_id, public_key):
        data = self._load()
        data[device_id] = {
            "public_key": public_key,
            "timestamp": time.time(),
            "status": "active"
        }
        self._save(data)

    def lookup_device(self, device_id):
        data = self._load()
        return data.get(device_id)

    def revoke_device(self, device_id):
        data = self._load()
        if device_id in data:
            data[device_id]["status"] = "revoked"
            self._save(data)
            return True
        return False