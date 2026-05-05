import hashlib
import json
import os
import time
from pathlib import Path

from crypto.key_generation import (
    generate_identity_key_pair,
    load_identity_private_key_from_hex,
    load_identity_public_key_from_hex,
    serialize_identity_private_key,
    serialize_identity_public_key,
    sign_message,
    verify_signature,
)


REGISTRY_FILE = "device_registry.json"
ADMIN_KEY_FILE = ".registry_admin.json"
GENESIS_HASH = "0" * 64
DEFAULT_NODE_DIR = ".registry_nodes"
DEFAULT_NODE_NAMES = ("node1", "node2", "node3")


class DeviceRegistry:
    def __init__(self, registry_file=REGISTRY_FILE, node_paths=None):
        self.registry_file = Path(registry_file)
        self.node_paths = self._resolve_node_paths(node_paths)
        self.admin_key_file = self.registry_file.parent / ADMIN_KEY_FILE
        self.admin_private_key, self.admin_public_key_hex = self._load_or_create_admin_identity()

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

    def _load_or_create_admin_identity(self):
        if self.admin_key_file.exists():
            data = json.loads(self.admin_key_file.read_text(encoding="utf-8"))
            return (
                load_identity_private_key_from_hex(data["private_key"]),
                data["public_key"],
            )

        private_key, public_key = generate_identity_key_pair()
        public_key_hex = serialize_identity_public_key(public_key)
        self.admin_key_file.write_text(
            json.dumps(
                {
                    "private_key": serialize_identity_private_key(private_key),
                    "public_key": public_key_hex,
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return private_key, public_key_hex

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

    def _read_all_registries(self):
        return [self._read_single_registry(path) for path in self.node_paths]

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
            "admin_public_key": self.admin_public_key_hex,
        }
        payload["event_hash"] = self._hash_event(payload)
        payload["admin_signature"] = sign_message(
            self.admin_private_key,
            payload["event_hash"].encode("utf-8"),
        )
        return payload

    def _hash_event(self, payload):
        canonical_payload = {
            "event_type": payload["event_type"],
            "device_id": payload["device_id"],
            "public_key": payload["public_key"],
            "status": payload["status"],
            "timestamp": payload["timestamp"],
            "prev_hash": payload["prev_hash"],
            "admin_public_key": payload["admin_public_key"],
        }
        canonical = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()

    def _validate_event_transition(self, devices, event_type, device_id, public_key):
        existing = devices.get(device_id)
        if event_type == "register":
            if existing is not None:
                raise RuntimeError(f"{device_id} already exists; use rotate or reenroll")
            return "active"
        if event_type == "revoke":
            if existing is None:
                raise RuntimeError(f"{device_id} does not exist")
            if existing["status"] != "active":
                raise RuntimeError(f"{device_id} is not active")
            return "revoked"
        if event_type == "rotate":
            if existing is None:
                raise RuntimeError(f"{device_id} does not exist")
            if existing["status"] != "active":
                raise RuntimeError(f"{device_id} must be active to rotate keys")
            if existing["public_key"] == public_key:
                raise RuntimeError(f"{device_id} already uses this key")
            return "active"
        if event_type == "reenroll":
            if existing is None:
                raise RuntimeError(f"{device_id} does not exist")
            if existing["status"] != "revoked":
                raise RuntimeError(f"{device_id} must be revoked before reenrollment")
            if existing["public_key"] == public_key:
                raise RuntimeError(f"{device_id} requires a new key for reenrollment")
            return "active"
        raise RuntimeError(f"Unsupported event type: {event_type}")

    def _majority_value(self, values):
        counts = {}
        for value in values:
            key = json.dumps(value, sort_keys=True)
            counts[key] = counts.get(key, 0) + 1
        best_key, best_count = max(counts.items(), key=lambda item: item[1])
        if best_count < 2:
            raise RuntimeError("Registry quorum not reached")
        return json.loads(best_key)

    def _majority_registry_data(self):
        return self._majority_value(self._read_all_registries())

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
                    "admin_public_key": event["admin_public_key"],
                }
            )
            admin_public_key = load_identity_public_key_from_hex(event["admin_public_key"])
            signature_ok = verify_signature(admin_public_key, event["event_hash"].encode("utf-8"), event["admin_signature"])
            if event["prev_hash"] != prev_hash or event["event_hash"] != expected_hash or not signature_ok:
                return False
            prev_hash = event["event_hash"]
        return True

    def get_replication_status(self):
        all_registries = self._read_all_registries()
        majority = self._majority_value(all_registries)
        node_status = []
        for path, node_data in zip(self.node_paths, all_registries):
            node_status.append(
                {
                    "node": path.stem,
                    "in_sync": node_data == majority,
                    "event_count": len(node_data["events"]),
                    "chain_valid": self.verify_chain_at_path(path),
                }
            )
        return node_status

    def verify_chain_at_path(self, path):
        data = self._read_single_registry(path)
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
                    "admin_public_key": event["admin_public_key"],
                }
            )
            admin_public_key = load_identity_public_key_from_hex(event["admin_public_key"])
            signature_ok = verify_signature(admin_public_key, event["event_hash"].encode("utf-8"), event["admin_signature"])
            if event["prev_hash"] != prev_hash or event["event_hash"] != expected_hash or not signature_ok:
                return False
            prev_hash = event["event_hash"]
        return True

    def repair_replication(self):
        majority = self._majority_registry_data()
        repaired_nodes = []
        for path in self.node_paths:
            node_data = self._read_single_registry(path)
            if node_data != majority:
                self._write_single_registry(path, majority)
                repaired_nodes.append(path.stem)
        self._write_single_registry(self.registry_file, majority)
        return {
            "repaired_nodes": repaired_nodes,
            "event_count": len(majority["events"]),
        }

    def register_device(self, device_id, public_key):
        data = self._read_registry()
        status = self._validate_event_transition(self._materialize_devices(data), "register", device_id, public_key)
        event = self._build_event("register", device_id, public_key, status, self._latest_hash(data))
        data["events"].append(event)
        self._write_registry(data)

    def lookup_device(self, device_id):
        registries = self._read_all_registries()
        device_views = [self._materialize_devices(data).get(device_id) for data in registries]
        if all(view is None for view in device_views):
            return None
        return self._majority_value(device_views)

    def list_devices(self):
        registries = self._read_all_registries()
        return self._majority_value([self._materialize_devices(data) for data in registries])

    def list_events(self):
        registries = self._read_all_registries()
        return self._majority_value([data["events"] for data in registries])

    def revoke_device(self, device_id):
        data = self._read_registry()
        devices = self._materialize_devices(data)
        status = self._validate_event_transition(devices, "revoke", device_id, devices.get(device_id, {}).get("public_key"))
        event = self._build_event("revoke", device_id, devices[device_id]["public_key"], status, self._latest_hash(data))
        data["events"].append(event)
        self._write_registry(data)
        return True

    def rotate_device_key(self, device_id, public_key):
        data = self._read_registry()
        devices = self._materialize_devices(data)
        status = self._validate_event_transition(devices, "rotate", device_id, public_key)
        event = self._build_event("rotate", device_id, public_key, status, self._latest_hash(data))
        data["events"].append(event)
        self._write_registry(data)
        return True

    def reenroll_device(self, device_id, public_key):
        data = self._read_registry()
        devices = self._materialize_devices(data)
        status = self._validate_event_transition(devices, "reenroll", device_id, public_key)
        event = self._build_event("reenroll", device_id, public_key, status, self._latest_hash(data))
        data["events"].append(event)
        self._write_registry(data)
        return True

    def reset_registry(self):
        self._write_registry({"events": []})
