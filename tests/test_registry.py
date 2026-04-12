import json

from blockchain.ledger import DeviceRegistry


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
