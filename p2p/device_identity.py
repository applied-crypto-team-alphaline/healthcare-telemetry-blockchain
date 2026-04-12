import json
import os
from pathlib import Path

from blockchain.ledger import DeviceRegistry
from crypto.key_generation import (
    generate_identity_key_pair,
    load_identity_private_key_from_hex,
    serialize_identity_private_key,
    serialize_identity_public_key,
)


KEY_DIR = Path(os.environ.get("DEVICE_KEY_DIR", ".device_keys"))


def _identity_path(device_id: str) -> Path:
    KEY_DIR.mkdir(exist_ok=True)
    return KEY_DIR / f"{device_id}.json"


def load_or_create_identity(device_id: str):
    identity_path = _identity_path(device_id)
    if identity_path.exists():
        data = json.loads(identity_path.read_text(encoding="utf-8"))
        private_key = load_identity_private_key_from_hex(data["private_key"])
        return {
            "device_id": device_id,
            "private_key": private_key,
            "public_key": data["public_key"],
        }

    private_key, public_key = generate_identity_key_pair()
    public_key_hex = serialize_identity_public_key(public_key)
    identity_path.write_text(
        json.dumps(
            {
                "device_id": device_id,
                "private_key": serialize_identity_private_key(private_key),
                "public_key": public_key_hex,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return {
        "device_id": device_id,
        "private_key": private_key,
        "public_key": public_key_hex,
    }


def ensure_registered_identity(device_id: str, registry: DeviceRegistry):
    identity = load_or_create_identity(device_id)
    record = registry.lookup_device(device_id)

    if record is None:
        registry.register_device(device_id, identity["public_key"])
    elif record["public_key"] != identity["public_key"] and record["status"] == "active":
        registry.register_device(device_id, identity["public_key"])

    return identity
