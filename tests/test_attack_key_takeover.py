from pathlib import Path

import p2p.device_identity as device_identity
from p2p.audit import key_id_from_public_key
from p2p.secure_channel import SecureChannel


def build_telemetry(device_id: str):
    return {
        "device_id": device_id,
        "patient_id": "P-attack-test",
        "sequence_number": 1,
        "heart_rate": 90,
        "oxygen_level": 97,
        "temperature": 36.9,
        "blood_pressure": "120/80",
        "timestamp": "2026-04-26T15:00:00Z",
        "ip_address": "127.0.0.1",
        "access_type": "App - Mobile",
        "action": "Data Upload",
        "target": 0,
    }


def test_active_device_key_can_be_silently_rebound(tmp_path):
    registry_file = tmp_path / "registry.json"
    legit_key_dir = tmp_path / "legit_keys"
    attacker_key_dir = tmp_path / "attacker_keys"

    channel = SecureChannel(registry_file=registry_file)
    channel.registry.reset_registry()
    channel.register_trusted_devices(["deviceA", "ICU_GATEWAY_01"])

    original_record = channel.registry.lookup_device("deviceA")
    original_key_id = key_id_from_public_key(original_record["public_key"])

    device_identity.KEY_DIR = Path(legit_key_dir)
    device_identity.ensure_registered_identity("deviceA", channel.registry)
    device_identity.KEY_DIR = Path(attacker_key_dir)
    attacker_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)

    hijacked_record = channel.registry.lookup_device("deviceA")
    hijacked_key_id = key_id_from_public_key(hijacked_record["public_key"])

    attacker_channel = SecureChannel(registry_file=registry_file)
    attacker_channel.device_identities["deviceA"] = {
        "private_key": attacker_identity["private_key"],
        "public_key": None,
        "public_key_hex": attacker_identity["public_key"],
    }

    result = attacker_channel.send_secure(
        "deviceA",
        "ICU_GATEWAY_01",
        build_telemetry("deviceA"),
    )

    assert hijacked_key_id != original_key_id
    assert result["authentication"]["verified"] is True
    assert result["decrypted"]["sender"] == "deviceA"
    assert result["decrypted"]["telemetry"]["patient_id"] == "P-attack-test"
