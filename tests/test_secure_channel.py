from p2p.device_emulator import generate_telemetry
from p2p.secure_channel import SecureChannel


def build_channel(tmp_path):
    channel = SecureChannel(registry_file=tmp_path / "registry.json")
    channel.registry.reset_registry()
    channel.register_trusted_devices(["deviceA", "deviceB"])
    return channel


def test_telemetry_generation():
    data = generate_telemetry()
    assert "heart_rate" in data
    assert "sequence_number" in data


def test_authenticated_handshake_verifies_registered_public_key(tmp_path):
    channel = build_channel(tmp_path)
    handshake = channel.start_handshake("deviceA", "deviceB")

    signature = channel.generate_handshake_proof(
        "deviceA",
        handshake["challenge"],
        handshake["sender_ephemeral_pub_hex"],
        handshake["receiver_ephemeral_pub_hex"],
    )

    assert channel.verify_handshake_proof(
        "deviceA",
        handshake["challenge"],
        handshake["sender_ephemeral_pub_hex"],
        handshake["receiver_ephemeral_pub_hex"],
        signature,
    )


def test_secure_send_returns_decrypted_payload(tmp_path):
    channel = build_channel(tmp_path)
    telemetry = {
        "device_id": "deviceA",
        "patient_id": "P-test",
        "sequence_number": 1,
        "heart_rate": 88,
        "oxygen_level": 97,
        "temperature": 36.8,
        "blood_pressure": "120/80",
        "timestamp": "2026-04-01T10:00:00Z",
        "ip_address": "127.0.0.1",
        "access_type": "App - Mobile",
        "action": "Data Upload",
        "target": 0,
    }

    result = channel.send_secure("deviceA", "deviceB", telemetry)

    assert result["decrypted"]["telemetry"]["patient_id"] == "P-test"
    assert result["decrypted"]["sender"] == "deviceA"
