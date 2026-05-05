import json
from pathlib import Path

from blockchain.ledger import DeviceRegistry


def main():
    demo_dir = Path(".tamper_demo")
    registry_file = demo_dir / "registry.json"
    node_paths = [demo_dir / "node1.json", demo_dir / "node2.json", demo_dir / "node3.json"]

    registry = DeviceRegistry(registry_file=registry_file, node_paths=node_paths)
    registry.reset_registry()
    registry.register_device("deviceA", "public-key-A")
    registry.revoke_device("deviceA")

    print("=== Tamper Detection Demo ===")
    print("Chain valid before tampering:", registry.verify_chain())
    print("Replication status before tampering:", registry.get_replication_status())

    tampered_data = json.loads(node_paths[0].read_text(encoding="utf-8"))
    tampered_data["events"][1]["status"] = "active"
    node_paths[0].write_text(json.dumps(tampered_data, indent=2), encoding="utf-8")

    print("Tampered field: node1 events[1].status -> active")
    print("Chain valid after tampering:", registry.verify_chain())
    print("Replication status after tampering:", registry.get_replication_status())


if __name__ == "__main__":
    main()
