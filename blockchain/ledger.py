import hashlib
import json
import os
import time
from pathlib import Path


REGISTRY_FILE = "device_registry.json"
GENESIS_HASH = "0" * 64
DEFAULT_NODE_DIR = ".registry_nodes"
DEFAULT_NODE_NAMES = ("node1", "node2", "node3")


class DeviceRegistry:
    def __init__(self, registry_file=REGISTRY_FILE, node_paths=None):
        self.registry_file = Path(registry_file)
        self.node_paths = self._resolve_node_paths(node_paths)

        for path in self.node_paths:
            path.parent.mkdir(parents=True, exist_ok=True)
            if not path.exists():
                self._write_single_registry(path, {"events": []})

        if not self.registry_file.exists():
            self._write_single_registry(self.registry_file, {"events": []})

    def _resolve_node_paths(self, node_paths):
        if node_paths:
            return [Path(path) for path in node_paths]

        node_dir = self.registry_file.parent / DEFAULT_NODE_DIR
        return [node_dir / f"{name}.json" for name in DEFAULT_NODE_NAMES]

    def _normalize_registry(self, data):
        if "events" in data:
            normalized = {"events": list(data["events"])}
            if "devices" in data and not data["events"]:
                for device_id, record in data["devices"].items():
                    normalized["events"].append(
                        self._build_event(
                            event_type="register",
                            device_id=device_id,
                            public_key=record["public_key"],
                            status=record["status"],
                            prev_hash=normalized["events"][-1]["event_hash"] if normalized["events"] else GENESIS_HASH,
                            timestamp=record["timestamp"],
                        )
                    )
            return normalized

        events = []
        for device_id, record in data.items():
            if not isinstance(record, dict):
                continue
            event_type = "revoke" if record.get("status") == "revoked" else "register"
            events.append(
                self._build_event(
                    event_type=event_type,
                    device_id=device_id,
                    public_key=record["public_key"],
                    status=record["status"],
                    prev_hash=events[-1]["event_hash"] if events else GENESIS_HASH,
                    timestamp=record["timestamp"],
                )
            )
        return {"events": events}

    def _read_single_registry(self, path):
        with open(path, "r", encoding="utf-8") as f:
            return self._normalize_registry(json.load(f))

    def _write_single_registry(self, path, data):
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def _read_registry(self):
        return self._read_single_registry(self.node_paths[0])

    def _write_registry(self, data):
        for path in self.node_paths:
            self._write_single_registry(path, data)
        self._write_single_registry(self.registry_file, data)

    def _build_event(self, event_type, device_id, public_key, status, prev_hash, timestamp=None):
        timestamp = time.time() if timestamp is None else timestamp
        payload = {
            "event_type": event_type,
            "device_id": device_id,
            "public_key": public_key,
            "status": status,
            "timestamp": timestamp,
            "prev_hash": prev_hash,
        }
        payload["event_hash"] = self._hash_event(payload)
        return payload

    def _hash_event(self, payload):
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _latest_hash(self, data):
        events = data["events"]
        return events[-1]["event_hash"] if events else GENESIS_HASH

    def _materialize_devices(self, data):
        devices = {}
        for event in data["events"]:
            devices[event["device_id"]] = {
                "public_key": event["public_key"],
                "timestamp": event["timestamp"],
                "status": event["status"],
            }
        return devices

    def verify_chain(self):
        data = self._read_registry()
        prev_hash = GENESIS_HASH
        for event in data["events"]:
            expected_hash = self._hash_event(
                {
                    "event_type": event["event_type"],
                    "device_id": event["device_id"],
                    "public_key": event["public_key"],
                    "status": event["status"],
                    "timestamp": event["timestamp"],
                    "prev_hash": event["prev_hash"],
                }
            )
            if event["prev_hash"] != prev_hash or event["event_hash"] != expected_hash:
                return False
            prev_hash = event["event_hash"]
        return True

    def get_replication_status(self):
        primary = self._read_single_registry(self.node_paths[0])
        node_status = []
        for path in self.node_paths:
            node_data = self._read_single_registry(path)
            node_status.append(
                {
                    "node": path.stem,
                    "in_sync": node_data == primary,
                    "event_count": len(node_data["events"]),
                }
            )
        return node_status

    def register_device(self, device_id, public_key):
        data = self._read_registry()
        event = self._build_event(
            event_type="register",
            device_id=device_id,
            public_key=public_key,
            status="active",
            prev_hash=self._latest_hash(data),
        )
        data["events"].append(event)
        self._write_registry(data)

    def lookup_device(self, device_id):
        data = self._read_registry()
        return self._materialize_devices(data).get(device_id)

    def list_devices(self):
        data = self._read_registry()
        return self._materialize_devices(data)

    def list_events(self):
        data = self._read_registry()
        return data["events"]

    def revoke_device(self, device_id):
        data = self._read_registry()
        devices = self._materialize_devices(data)
        if device_id not in devices:
            return False

        event = self._build_event(
            event_type="revoke",
            device_id=device_id,
            public_key=devices[device_id]["public_key"],
            status="revoked",
            prev_hash=self._latest_hash(data),
        )
        data["events"].append(event)
        self._write_registry(data)
        return True

    def reset_registry(self):
        self._write_registry({"events": []})
