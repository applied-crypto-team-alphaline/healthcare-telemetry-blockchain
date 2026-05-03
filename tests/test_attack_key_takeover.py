from pathlib import Path

import pytest

import p2p.device_identity as device_identity
from p2p.audit import key_id_from_public_key
from p2p.secure_channel import SecureChannel


@pytest.fixture(autouse=True)
def restore_identity_key_dir():
    original_key_dir = device_identity.KEY_DIR
    yield
    device_identity.KEY_DIR = original_key_dir


def test_active_device_key_rebinding_is_rejected(tmp_path):
    registry_file = tmp_path / "registry.json"
    legit_key_dir = tmp_path / "legit_keys"
    attacker_key_dir = tmp_path / "attacker_keys"

    channel = SecureChannel(registry_file=registry_file)
    channel.registry.reset_registry()
    channel.register_trusted_devices(["ICU_GATEWAY_01"])

    device_identity.KEY_DIR = Path(legit_key_dir)
    legit_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)

    original_record = channel.registry.lookup_device("deviceA")
    original_key_id = key_id_from_public_key(original_record["public_key"])

    assert original_key_id == key_id_from_public_key(legit_identity["public_key"])
    device_identity.KEY_DIR = Path(attacker_key_dir)

    with pytest.raises(RuntimeError, match="already bound to a different active key"):
        device_identity.ensure_registered_identity("deviceA", channel.registry)

    final_record = channel.registry.lookup_device("deviceA")
    final_key_id = key_id_from_public_key(final_record["public_key"])

    assert final_key_id == original_key_id


def test_matching_active_identity_is_idempotent(tmp_path):
    registry_file = tmp_path / "registry.json"
    key_dir = tmp_path / "same_keys"

    channel = SecureChannel(registry_file=registry_file)
    channel.registry.reset_registry()

    device_identity.KEY_DIR = Path(key_dir)
    first_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)
    initial_events = len(channel.registry.list_events())

    second_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)

    assert second_identity["public_key"] == first_identity["public_key"]
    assert len(channel.registry.list_events()) == initial_events


def test_revoked_device_cannot_self_reenroll(tmp_path):
    registry_file = tmp_path / "registry.json"
    revoked_key_dir = tmp_path / "revoked_keys"
    attacker_key_dir = tmp_path / "attacker_keys"

    channel = SecureChannel(registry_file=registry_file)
    channel.registry.reset_registry()

    device_identity.KEY_DIR = Path(revoked_key_dir)
    original_identity = device_identity.ensure_registered_identity("deviceA", channel.registry)
    channel.revoke_device("deviceA")

    device_identity.KEY_DIR = Path(attacker_key_dir)
    with pytest.raises(RuntimeError, match="requires explicit re-enrollment"):
        device_identity.ensure_registered_identity("deviceA", channel.registry)

    final_record = channel.registry.lookup_device("deviceA")
    assert final_record["status"] == "revoked"
    assert final_record["public_key"] == original_identity["public_key"]
