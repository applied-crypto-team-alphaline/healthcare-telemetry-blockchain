import json
import socket
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from blockchain.ledger import DeviceRegistry
from crypto.key_generation import (
    generate_identity_key_pair,
    serialize_identity_public_key,
    generate_exchange_key_pair,
)
from crypto.key_exchange import derive_shared_secret, derive_session_key
from crypto.encryption import encrypt_message
from p2p.device_emulator import generate_telemetry

HOST = "127.0.0.1"
PORT = 5001


def verify_device(registry, device_id):
    record = registry.lookup_device(device_id)
    if not record:
        print(f"[CLIENT] {device_id} not found")
        return False
    if record["status"] != "active":
        print(f"[CLIENT] {device_id} is revoked")
        return False
    return True


def recv_json(sock: socket.socket):
    raw = sock.recv(8192)
    if not raw:
        return None
    text = raw.decode("utf-8").strip()
    print(f"[CLIENT] Raw received: {text}")
    if not text:
        return None
    return json.loads(text)


def send_json(sock: socket.socket, payload: dict):
    data = json.dumps(payload).encode("utf-8")
    sock.sendall(data)


def main():
    registry = DeviceRegistry()

    # Register deviceA identity
    _, a_public = generate_identity_key_pair()
    registry.register_device("deviceA", serialize_identity_public_key(a_public))
    print("[CLIENT] deviceA registered")

    if not verify_device(registry, "deviceB"):
        print("[CLIENT] deviceB must be registered first")
        return

    # Key exchange key pair
    a_kx_priv, a_kx_pub = generate_exchange_key_pair()
    a_kx_pub_hex = a_kx_pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()

    # CLIENT SOCKET: connect only, no bind/listen
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))

    # Step 1: send hello
    hello = {
        "device_id": "deviceA",
        "kx_public": a_kx_pub_hex
    }
    send_json(client, hello)

    # Step 2: receive server hello
    server_hello = recv_json(client)
    if server_hello is None:
        print("[CLIENT] No response from server")
        client.close()
        return

    if server_hello["status"] != "ok":
        print("[CLIENT] Connection rejected")
        client.close()
        return

    # Step 3: derive session key
    b_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(server_hello["kx_public"]))
    shared_secret = derive_shared_secret(a_kx_priv, b_pub)
    session_key = derive_session_key(shared_secret)

    # Step 4: send encrypted telemetry
    telemetry = generate_telemetry()
    plaintext = json.dumps(telemetry)

    nonce, ciphertext = encrypt_message(session_key, plaintext)

    payload = {
        "sequence_number": telemetry["sequence_number"],
        "nonce": nonce,
        "ciphertext": ciphertext
    }

    send_json(client, payload)
    print("[CLIENT] Sent encrypted telemetry")

    client.close()


if __name__ == "__main__":
    main()