import pytest

from p2p.audit import get_audit_log_path
from p2p.device_a import tamper_signature
from p2p.secure_channel import SecureChannel


def build_channel(tmp_path):
    channel = SecureChannel(registry_file=tmp_path / "registry.json")
    channel.registry.reset_registry()
    channel.register_trusted_devices(["deviceA", "deviceB"])
    return channel


def test_replay_detection(tmp_path):
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

    channel.send_secure("deviceA", "deviceB", telemetry)

    with pytest.raises(Exception, match="Replay attack detected"):
        channel.send_secure("deviceA", "deviceB", telemetry)


def test_invalid_signature_is_rejected(tmp_path):
    channel = build_channel(tmp_path)
    handshake = channel.start_handshake("deviceA", "deviceB")
    bad_signature = tamper_signature(
        channel.generate_handshake_proof(
            "deviceA",
            handshake["challenge"],
            handshake["sender_ephemeral_pub_hex"],
            handshake["receiver_ephemeral_pub_hex"],
        )
    )

    with pytest.raises(Exception, match="authentication proof failed"):
        channel.verify_handshake_proof(
            "deviceA",
            handshake["challenge"],
            handshake["sender_ephemeral_pub_hex"],
            handshake["receiver_ephemeral_pub_hex"],
            bad_signature,
        )


def test_replay_detection_writes_audit_log(tmp_path, monkeypatch):
    audit_log = tmp_path / "security_audit.log"
    monkeypatch.setenv("AUDIT_LOG_FILE", str(audit_log))

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

    channel.send_secure("deviceA", "deviceB", telemetry)

    with pytest.raises(Exception, match="Replay attack detected"):
        channel.send_secure("deviceA", "deviceB", telemetry)

    assert get_audit_log_path() == audit_log
    log_contents = audit_log.read_text(encoding="utf-8")
    assert '"event_type": "replay_detected"' in log_contents
    assert '"sender": "deviceA"' in log_contents
