import json

import pytest

from blockchain.ledger import DeviceRegistry


def tamper_hex(hex_value):
    tampered = bytearray.fromhex(hex_value)
    tampered[-1] ^= 0x01
    return bytes(tampered).hex()


def test_register_and_lookup(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)
    registry.register_device("device1", "public-key-hex")

    record = registry.lookup_device("device1")
    events = registry.list_events()

    assert record is not None
    assert record["public_key"] == "public-key-hex"
    assert record["status"] == "active"
    assert events[-1]["event_type"] == "register"
    assert events[-1]["prev_hash"] == "0" * 64
    assert "event_hash" in events[-1]
    assert "admin_signature" in events[-1]
    assert "admin_public_key" in events[-1]
    assert registry.verify_chain()
    assert all(node["in_sync"] for node in registry.get_replication_status())


def test_revocation(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)
    registry.register_device("device1", "public-key-hex")

    registry.revoke_device("device1")
    record = registry.lookup_device("device1")
    events = registry.list_events()

    assert record["status"] == "revoked"
    assert events[-1]["event_type"] == "revoke"
    assert events[-1]["prev_hash"] == events[0]["event_hash"]
    assert registry.verify_chain()
    assert all(node["in_sync"] for node in registry.get_replication_status())


def test_replication_creates_identical_node_ledgers(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-hex")
    registry.revoke_device("device1")

    contents = [path.read_text(encoding="utf-8") for path in node_paths]
    assert contents[0] == contents[1] == contents[2]


def test_tampered_event_breaks_chain_verification(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-hex")
    registry.revoke_device("device1")

    tampered_data = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_data["events"][1]["status"] = "active"
    node_paths[0].write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    assert not registry.verify_chain()


def test_replication_status_detects_node_mismatch(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-hex")

    desynced_data = json.loads(node_paths[1].read_text(encoding="utf-8"))
    desynced_data["events"][0]["status"] = "revoked"
    node_paths[1].write_text(json.dumps(desynced_data, indent=2), encoding="utf-8")

    node_status = registry.get_replication_status()

    assert node_status[0]["in_sync"] is True
    assert node_status[1]["in_sync"] is False
    assert node_status[2]["in_sync"] is True


def test_rotate_device_key_appends_rotate_event(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")
    registry.rotate_device_key("device1", "public-key-v2")

    record = registry.lookup_device("device1")
    events = registry.list_events()

    assert record["public_key"] == "public-key-v2"
    assert record["status"] == "active"
    assert events[-1]["event_type"] == "rotate"
    assert registry.verify_chain()


def test_reenroll_requires_revoked_device_and_new_key(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")
    registry.revoke_device("device1")
    registry.reenroll_device("device1", "public-key-v2")

    record = registry.lookup_device("device1")
    events = registry.list_events()

    assert record["public_key"] == "public-key-v2"
    assert record["status"] == "active"
    assert events[-1]["event_type"] == "reenroll"
    assert registry.verify_chain()


def test_active_device_cannot_be_reregistered_or_reenrolled(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")

    with pytest.raises(RuntimeError, match="already exists; use rotate or reenroll"):
        registry.register_device("device1", "public-key-v2")

    with pytest.raises(RuntimeError, match="must be revoked before reenrollment"):
        registry.reenroll_device("device1", "public-key-v2")


def test_lookup_device_uses_majority_quorum(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")

    tampered_data = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_data["events"][0]["public_key"] = "bad-key"
    node_paths[0].write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    record = registry.lookup_device("device1")
    assert record["public_key"] == "public-key-v1"


def test_tampered_admin_signature_breaks_chain_verification(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")

    tampered_data = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_data["events"][0]["admin_signature"] = tamper_hex(tampered_data["events"][0]["admin_signature"])
    node_paths[0].write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    assert not registry.verify_chain()


def test_repair_replication_restores_majority_copy(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")
    registry.rotate_device_key("device1", "public-key-v2")

    tampered_data = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_data["events"][1]["public_key"] = "bad-key"
    node_paths[0].write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    before_status = registry.get_replication_status()
    repair_result = registry.repair_replication()
    after_status = registry.get_replication_status()

    assert before_status[0]["in_sync"] is False
    assert "node1" in repair_result["repaired_nodes"]
    assert all(node["in_sync"] for node in after_status)
    assert registry.lookup_device("device1")["public_key"] == "public-key-v2"


def test_quorum_failure_is_fail_closed(tmp_path):
    node_paths = [tmp_path / "node1.json", tmp_path / "node2.json", tmp_path / "node3.json"]
    registry = DeviceRegistry(registry_file=tmp_path / "registry.json", node_paths=node_paths)

    registry.register_device("device1", "public-key-v1")

    tampered_one = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_one["events"][0]["public_key"] = "bad-key-1"
    node_paths[0].write_text(json.dumps(tampered_one, indent=2), encoding="utf-8")

    tampered_two = json.loads(node_paths[1].read_text(encoding="utf-8"))
    tampered_two["events"][0]["public_key"] = "bad-key-2"
    node_paths[1].write_text(json.dumps(tampered_two, indent=2), encoding="utf-8")

    with pytest.raises(RuntimeError, match="Registry quorum not reached"):
        registry.lookup_device("device1")
