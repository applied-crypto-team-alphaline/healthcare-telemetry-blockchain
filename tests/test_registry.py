from blockchain.ledger import DeviceRegistry


def test_register_and_lookup():
    registry = DeviceRegistry()
    registry.register_device("device1", "pubkey")

    record = registry.lookup_device("device1")
    assert record is not None
    assert record["status"] == "active"


def test_revocation():
    registry = DeviceRegistry()
    registry.register_device("device1", "pubkey")

    registry.revoke_device("device1")
    record = registry.lookup_device("device1")

    assert record["status"] == "revoked"