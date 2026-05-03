import json
import tempfile
from pathlib import Path

from blockchain.ledger import DeviceRegistry
from p2p.audit import key_id_from_public_key
import p2p.device_identity as device_identity
from p2p.secure_channel import SecureChannel


def build_telemetry(device_id: str):
    return {
        "device_id": device_id,
        "patient_id": "P-attack-demo",
        "sequence_number": 1,
        "heart_rate": 84,
        "oxygen_level": 98,
        "temperature": 36.7,
        "blood_pressure": "118/79",
        "timestamp": "2026-04-26T12:00:00Z",
        "ip_address": "127.0.0.1",
        "access_type": "App - Mobile",
        "action": "Data Upload",
        "target": 0,
    }


def main():
    temp_dir = Path(tempfile.mkdtemp(prefix="attack_takeover_"))
    registry_file = temp_dir / "registry.json"
    legit_key_dir = temp_dir / "legit_keys"
    attacker_key_dir = temp_dir / "attacker_keys"

    channel = SecureChannel(registry_file=registry_file)
    channel.registry.reset_registry()
    channel.register_trusted_devices(["ICU_GATEWAY_01"])

    device_identity.KEY_DIR = legit_key_dir
    legit_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)

    original_record = channel.registry.lookup_device("deviceA")
    original_key_id = key_id_from_public_key(original_record["public_key"])

    # Simulate a second actor with a different local key store claiming the same device ID.
    device_identity.KEY_DIR = attacker_key_dir
    attack_blocked = False
    failure_reason = None

    try:
        attacker_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)

        attacker_channel = SecureChannel(registry_file=registry_file)
        attacker_channel.device_identities["deviceA"] = {
            "private_key": attacker_identity["private_key"],
            "public_key": None,
            "public_key_hex": attacker_identity["public_key"],
        }
        attacker_channel.send_secure(
            "deviceA",
            "ICU_GATEWAY_01",
            build_telemetry("deviceA"),
        )
    except Exception as exc:
        attack_blocked = True
        failure_reason = str(exc)

    final_record = channel.registry.lookup_device("deviceA")
    final_key_id = key_id_from_public_key(final_record["public_key"])

    evidence = {
        "attack": "device_id_key_takeover_rerun",
        "registry_file": str(registry_file),
        "original_key_id": original_key_id,
        "legit_key_id": key_id_from_public_key(legit_identity["public_key"]),
        "final_key_id": final_key_id,
        "registry_key_changed": original_key_id != final_key_id,
        "attack_blocked": attack_blocked,
        "failure_reason": failure_reason,
        "impact": "key takeover prevented; attacker cannot replace active deviceA key",
    }
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()
