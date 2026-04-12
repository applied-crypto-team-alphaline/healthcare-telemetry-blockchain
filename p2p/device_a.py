import json
import os
import socket

from blockchain.ledger import DeviceRegistry
from crypto.encryption import encrypt_message
from crypto.key_exchange import derive_session_key, derive_shared_secret
from crypto.key_generation import (
    generate_exchange_key_pair,
    load_exchange_public_key_from_hex,
    serialize_exchange_public_key,
    sign_message,
)
from p2p.device_emulator import generate_telemetry
from p2p.device_identity import ensure_registered_identity
from p2p.secure_channel import build_handshake_message


HOST = os.environ.get("P2P_HOST", "127.0.0.1")
PORT = int(os.environ.get("P2P_PORT", "5001"))
DEVICE_ID = os.environ.get("P2P_DEVICE_ID", "deviceA")
RECEIVER_ID = os.environ.get("P2P_RECEIVER_ID", "ICU_GATEWAY_01")
REGISTRY_FILE = os.environ.get("P2P_REGISTRY_FILE")
TAMPER_SIGNATURE = os.environ.get("P2P_TAMPER_SIGNATURE", "0") == "1"


def send_json(sock: socket.socket, payload: dict):
    sock.sendall((json.dumps(payload) + "\n").encode("utf-8"))


def recv_json(sock_file):
    line = sock_file.readline()
    if not line:
        return None
    return json.loads(line)


def maybe_print_rejection(message):
    if message and message.get("status") == "rejected":
        print(json.dumps(message, indent=2))
        return True
    return False


def tamper_signature(signature_hex: str) -> str:
    signature_bytes = bytearray.fromhex(signature_hex)
    signature_bytes[-1] ^= 0x01
    return bytes(signature_bytes).hex()


def main():
    registry = DeviceRegistry(registry_file=REGISTRY_FILE) if REGISTRY_FILE else DeviceRegistry()
    identity = ensure_registered_identity(DEVICE_ID, registry)

    sender_exchange_private, sender_exchange_public = generate_exchange_key_pair()
    sender_ephemeral_pub_hex = serialize_exchange_public_key(sender_exchange_public)

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((HOST, PORT))
    sock_file = client.makefile("r")

    send_json(
        client,
        {
            "message_type": "hello",
            "device_id": DEVICE_ID,
            "receiver_id": RECEIVER_ID,
            "sender_ephemeral_pub_hex": sender_ephemeral_pub_hex,
        },
    )

    challenge_message = recv_json(sock_file)
    if maybe_print_rejection(challenge_message):
        sock_file.close()
        client.close()
        return
    if not challenge_message or challenge_message.get("message_type") != "challenge":
        raise RuntimeError("Did not receive challenge from receiver")

    challenge_hex = challenge_message["challenge"]
    receiver_ephemeral_pub_hex = challenge_message["receiver_ephemeral_pub_hex"]

    signature = sign_message(
        identity["private_key"],
        build_handshake_message(
            DEVICE_ID,
            challenge_hex,
            sender_ephemeral_pub_hex,
            receiver_ephemeral_pub_hex,
        ),
    )
    if TAMPER_SIGNATURE:
        signature = tamper_signature(signature)

    send_json(
        client,
        {
            "message_type": "proof",
            "device_id": DEVICE_ID,
            "signature": signature,
        },
    )

    client.settimeout(0.2)
    try:
        proof_response = recv_json(sock_file)
    except socket.timeout:
        proof_response = None
    finally:
        client.settimeout(None)

    if maybe_print_rejection(proof_response):
        sock_file.close()
        client.close()
        return

    receiver_pub = load_exchange_public_key_from_hex(receiver_ephemeral_pub_hex)
    session_key = derive_session_key(derive_shared_secret(sender_exchange_private, receiver_pub))

    telemetry = generate_telemetry()
    telemetry["device_id"] = DEVICE_ID
    payload = {
        "sender": DEVICE_ID,
        "receiver": RECEIVER_ID,
        "telemetry": telemetry,
    }
    nonce, ciphertext = encrypt_message(session_key, json.dumps(payload))

    send_json(
        client,
        {
            "message_type": "telemetry",
            "sequence_number": telemetry["sequence_number"],
            "nonce": nonce,
            "ciphertext": ciphertext,
        },
    )

    response = recv_json(sock_file)
    if response:
        print(json.dumps(response, indent=2))

    sock_file.close()
    client.close()


if __name__ == "__main__":
    main()
