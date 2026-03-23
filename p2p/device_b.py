import json
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from blockchain.ledger import DeviceRegistry
from crypto.key_generation import (
    generate_identity_key_pair,
    serialize_identity_public_key,
    generate_exchange_key_pair,
    serialize_exchange_public_key,
)
from crypto.key_exchange import derive_shared_secret, derive_session_key
from crypto.encryption import decrypt_message

HOST = "127.0.0.1"
PORT = 5001
seen_sequences = set()


def verify_device(registry: DeviceRegistry, device_id: str) -> bool:
    record = registry.lookup_device(device_id)
    if not record:
        print(f"[SERVER] {device_id} not found in registry")
        return False
    if record["status"] != "active":
        print(f"[SERVER] {device_id} is revoked")
        return False
    return True


def recv_json(conn: socket.socket):
    raw = conn.recv(8192)
    if not raw:
        return None
    text = raw.decode("utf-8").strip()
    print(f"[SERVER] Raw received: {text}")
    if not text:
        return None
    return json.loads(text)


def send_json(conn: socket.socket, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    conn.sendall(data)


def main():
    registry = DeviceRegistry()

    # Register deviceB identity
    _, identity_public = generate_identity_key_pair()
    identity_public_hex = serialize_identity_public_key(identity_public)
    registry.register_device("deviceB", identity_public_hex)
    print("[SERVER] deviceB registered")

    # Key exchange key pair
    b_kx_priv, b_kx_pub = generate_exchange_key_pair()
    b_kx_pub_hex = b_kx_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)

    print("[SERVER] Listening on", PORT)
    conn, addr = server.accept()
    print("[SERVER] Connected by", addr)

    # Step 1: receive hello
    hello = recv_json(conn)
    if hello is None:
        print("[SERVER] No client hello received")
        conn.close()
        server.close()
        return

    client_id = hello["device_id"]
    client_pub_hex = hello["kx_public"]

    if not verify_device(registry, client_id):
        send_json(conn, {"status": "rejected"})
        conn.close()
        server.close()
        return

    # Step 2: send server hello
    server_hello = {
        "status": "ok",
        "device_id": "deviceB",
        "kx_public": b_kx_pub_hex
    }
    send_json(conn, server_hello)

    # Step 3: derive session key
    a_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(client_pub_hex))
    shared_secret = derive_shared_secret(b_kx_priv, a_pub)
    session_key = derive_session_key(shared_secret)

    # Step 4: receive encrypted telemetry
    payload = recv_json(conn)
    if payload is None:
        print("[SERVER] No encrypted payload received")
        conn.close()
        server.close()
        return

    seq = payload["sequence_number"]
    if seq in seen_sequences:
        print("[SERVER] Replay attack detected")
        conn.close()
        server.close()
        return
    seen_sequences.add(seq)

    plaintext = decrypt_message(session_key, payload["nonce"], payload["ciphertext"])
    print("[SERVER] Decrypted telemetry:", plaintext)

    conn.close()
    server.close()


if __name__ == "__main__":
    main()