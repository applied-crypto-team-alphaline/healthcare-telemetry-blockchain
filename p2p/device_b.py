import json
import os
import socket

from blockchain.ledger import DeviceRegistry
from crypto.encryption import decrypt_message
from crypto.key_exchange import derive_session_key, derive_shared_secret
from crypto.key_generation import (
    generate_exchange_key_pair,
    load_exchange_public_key_from_hex,
    load_identity_public_key_from_hex,
    serialize_exchange_public_key,
    verify_signature,
)
from p2p.device_identity import ensure_registered_identity
from p2p.secure_channel import build_handshake_message


HOST = os.environ.get("P2P_HOST", "127.0.0.1")
PORT = int(os.environ.get("P2P_PORT", "5001"))
DEVICE_ID = os.environ.get("P2P_DEVICE_ID", "ICU_GATEWAY_01")
REGISTRY_FILE = os.environ.get("P2P_REGISTRY_FILE")


def send_json(conn: socket.socket, payload: dict):
    conn.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def recv_json(conn_file):
    line = conn_file.readline()
    if not line:
        return None
    return json.loads(line)


def main():
    registry = DeviceRegistry(registry_file=REGISTRY_FILE) if REGISTRY_FILE else DeviceRegistry()
    ensure_registered_identity(DEVICE_ID, registry)
    seen_sequences = set()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    conn_file = conn.makefile("r")
    print(f"[SERVER] Connected by {addr}")

    hello = recv_json(conn_file)
    if not hello or hello.get("message_type") != "hello":
        raise RuntimeError("Did not receive valid hello message")

    sender_id = hello["device_id"]
    sender_record = registry.lookup_device(sender_id)
    if not sender_record:
        send_json(conn, {"status": "rejected", "error": "ERR_DEVICE_NOT_REGISTERED"})
        conn.close()
        server.close()
        return
    if sender_record["status"] != "active":
        send_json(conn, {"status": "rejected", "error": "ERR_DEVICE_REVOKED"})
        conn.close()
        server.close()
        return

    receiver_exchange_private, receiver_exchange_public = generate_exchange_key_pair()
    receiver_ephemeral_pub_hex = serialize_exchange_public_key(receiver_exchange_public)
    challenge_hex = socket.randbytes(16).hex() if hasattr(socket, "randbytes") else __import__("os").urandom(16).hex()

    send_json(
        conn,
        {
            "message_type": "challenge",
            "challenge": challenge_hex,
            "receiver_ephemeral_pub_hex": receiver_ephemeral_pub_hex,
        },
    )

    proof = recv_json(conn_file)
    if not proof or proof.get("message_type") != "proof":
        raise RuntimeError("Did not receive valid proof message")

    sender_ephemeral_pub_hex = hello["sender_ephemeral_pub_hex"]
    signature = proof["signature"]
    message = build_handshake_message(
        sender_id,
        challenge_hex,
        sender_ephemeral_pub_hex,
        receiver_ephemeral_pub_hex,
    )
    sender_public_key = load_identity_public_key_from_hex(sender_record["public_key"])

    if not verify_signature(sender_public_key, message, signature):
        send_json(conn, {"status": "rejected", "error": "ERR_AUTH_PROOF_FAILED"})
        conn.close()
        server.close()
        return

    sender_pub = load_exchange_public_key_from_hex(sender_ephemeral_pub_hex)
    session_key = derive_session_key(derive_shared_secret(receiver_exchange_private, sender_pub))

    telemetry_message = recv_json(conn_file)
    if not telemetry_message or telemetry_message.get("message_type") != "telemetry":
        raise RuntimeError("Did not receive telemetry message")

    seq_key = (sender_id, telemetry_message["sequence_number"])
    if seq_key in seen_sequences:
        send_json(conn, {"status": "rejected", "error": "ERR_REPLAY_DETECTED"})
        conn.close()
        server.close()
        return
    seen_sequences.add(seq_key)

    plaintext = decrypt_message(session_key, telemetry_message["nonce"], telemetry_message["ciphertext"])
    decrypted_payload = json.loads(plaintext)

    send_json(
        conn,
        {
            "status": "accepted",
            "sender": sender_id,
            "verified": True,
            "telemetry": decrypted_payload["telemetry"],
        },
    )

    conn_file.close()
    conn.close()
    server.close()


if __name__ == "__main__":
    main()
