import time


class DeviceRegistry:
    def __init__(self):
        self.records = {}

    def register_device(self, device_id, public_key):
        self.records[device_id] = {
            "public_key": public_key,
            "timestamp": time.time(),
            "status": "active"
        }

    def lookup_device(self, device_id):
        return self.records.get(device_id)

    def revoke_device(self, device_id):
        if device_id in self.records:
            self.records[device_id]["status"] = "revoked"
            return True
        return False
