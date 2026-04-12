import json
import os

from blockchain.ledger import DeviceRegistry
from crypto.encryption import decrypt_message, encrypt_message
from crypto.key_exchange import derive_session_key, derive_shared_secret
from crypto.key_generation import (
    generate_exchange_key_pair,
    generate_identity_key_pair,
    load_exchange_public_key_from_hex,
    load_identity_public_key_from_hex,
    serialize_exchange_public_key,
    serialize_identity_public_key,
    sign_message,
    verify_signature,
)
from p2p.device_emulator import generate_telemetry, get_unique_devices


def build_handshake_message(device_id, challenge_hex, sender_ephemeral_pub_hex, receiver_ephemeral_pub_hex):
    parts = [
        device_id,
        challenge_hex,
        sender_ephemeral_pub_hex,
        receiver_ephemeral_pub_hex,
    ]
    return "|".join(parts).encode("utf-8")


class SecureChannel:
    def __init__(self, registry_file=None):
        self.registry = DeviceRegistry(registry_file=registry_file) if registry_file else DeviceRegistry()
        self.device_identities = {}
        self.seen_sequences = set()

    def register_device(self, device_id):
        private_key, public_key = generate_identity_key_pair()
        public_key_hex = serialize_identity_public_key(public_key)
        self.registry.register_device(device_id, public_key_hex)
        self.device_identities[device_id] = {
            "private_key": private_key,
            "public_key": public_key,
            "public_key_hex": public_key_hex,
        }
        return {
            "device_id": device_id,
            "public_key": public_key_hex,
        }

    def register_trusted_devices(self, trusted_devices):
        return [self.register_device(device_id) for device_id in trusted_devices]

    def verify_device(self, device_id):
        record = self.registry.lookup_device(device_id)
        if not record:
            raise Exception(f"{device_id} is not registered")
        if record["status"] != "active":
            raise Exception(f"{device_id} is revoked")
        return record

    def build_handshake_message(self, device_id, challenge_hex, sender_ephemeral_pub_hex, receiver_ephemeral_pub_hex):
        return build_handshake_message(
            device_id,
            challenge_hex,
            sender_ephemeral_pub_hex,
            receiver_ephemeral_pub_hex,
        )

    def start_handshake(self, sender, receiver):
        self.verify_device(sender)
        self.verify_device(receiver)

        sender_exchange_private, sender_exchange_public = generate_exchange_key_pair()
        receiver_exchange_private, receiver_exchange_public = generate_exchange_key_pair()
        challenge_hex = os.urandom(16).hex()

        return {
            "sender": sender,
            "receiver": receiver,
            "challenge": challenge_hex,
            "sender_exchange_private": sender_exchange_private,
            "receiver_exchange_private": receiver_exchange_private,
            "sender_ephemeral_pub_hex": serialize_exchange_public_key(sender_exchange_public),
            "receiver_ephemeral_pub_hex": serialize_exchange_public_key(receiver_exchange_public),
        }

    def generate_handshake_proof(self, sender, challenge_hex, sender_ephemeral_pub_hex, receiver_ephemeral_pub_hex):
        if sender not in self.device_identities:
            raise Exception(f"Missing local identity for {sender}")

        message = self.build_handshake_message(
            sender,
            challenge_hex,
            sender_ephemeral_pub_hex,
            receiver_ephemeral_pub_hex,
        )
        return sign_message(self.device_identities[sender]["private_key"], message)

    def verify_handshake_proof(
        self,
        sender,
        challenge_hex,
        sender_ephemeral_pub_hex,
        receiver_ephemeral_pub_hex,
        signature_hex,
    ):
        record = self.verify_device(sender)
        message = self.build_handshake_message(
            sender,
            challenge_hex,
            sender_ephemeral_pub_hex,
            receiver_ephemeral_pub_hex,
        )
        identity_public_key = load_identity_public_key_from_hex(record["public_key"])

        if not verify_signature(identity_public_key, message, signature_hex):
            raise Exception(f"{sender} authentication proof failed")

        return {
            "device_id": sender,
            "verified": True,
            "registry_public_key": record["public_key"],
            "challenge": challenge_hex,
            "signature": signature_hex,
        }

    def establish_authenticated_session(self, sender, receiver):
        handshake = self.start_handshake(sender, receiver)
        signature_hex = self.generate_handshake_proof(
            sender,
            handshake["challenge"],
            handshake["sender_ephemeral_pub_hex"],
            handshake["receiver_ephemeral_pub_hex"],
        )
        authentication = self.verify_handshake_proof(
            sender,
            handshake["challenge"],
            handshake["sender_ephemeral_pub_hex"],
            handshake["receiver_ephemeral_pub_hex"],
            signature_hex,
        )

        receiver_pub = load_exchange_public_key_from_hex(handshake["receiver_ephemeral_pub_hex"])
        sender_pub = load_exchange_public_key_from_hex(handshake["sender_ephemeral_pub_hex"])

        sender_shared_secret = derive_shared_secret(handshake["sender_exchange_private"], receiver_pub)
        receiver_shared_secret = derive_shared_secret(handshake["receiver_exchange_private"], sender_pub)

        sender_session_key = derive_session_key(sender_shared_secret)
        receiver_session_key = derive_session_key(receiver_shared_secret)

        return {
            "authentication": authentication,
            "session_establishment": {
                "sender_ephemeral_pub_hex": handshake["sender_ephemeral_pub_hex"],
                "receiver_ephemeral_pub_hex": handshake["receiver_ephemeral_pub_hex"],
                "sender_session_key": sender_session_key,
                "receiver_session_key": receiver_session_key,
            },
        }

    def send_secure(self, sender, receiver, telemetry):
        if telemetry["device_id"] != sender:
            raise Exception("Spoofing detected")

        seq_key = (sender, telemetry["sequence_number"])
        if seq_key in self.seen_sequences:
            raise Exception("Replay attack detected")

        session = self.establish_authenticated_session(sender, receiver)
        self.seen_sequences.add(seq_key)

        plaintext = json.dumps(
            {
                "sender": sender,
                "receiver": receiver,
                "telemetry": telemetry,
            }
        )
        nonce, ciphertext = encrypt_message(
            session["session_establishment"]["sender_session_key"],
            plaintext,
        )
        decrypted = decrypt_message(
            session["session_establishment"]["receiver_session_key"],
            nonce,
            ciphertext,
        )

        return {
            "authentication": session["authentication"],
            "session_establishment": {
                "sender_ephemeral_pub_hex": session["session_establishment"]["sender_ephemeral_pub_hex"],
                "receiver_ephemeral_pub_hex": session["session_establishment"]["receiver_ephemeral_pub_hex"],
                "verified": True,
            },
            "encryption": {
                "nonce": nonce,
                "ciphertext": ciphertext,
                "algorithm": "AES-GCM",
            },
            "decrypted": json.loads(decrypted),
        }

    def revoke_device(self, device_id):
        self.registry.revoke_device(device_id)


def run_demo():
    channel = SecureChannel()
    channel.registry.reset_registry()

    all_devices = get_unique_devices()
    trusted_devices = all_devices[:20]
    gateway = "ICU_GATEWAY_01"
    trusted_devices.append(gateway)
    channel.register_trusted_devices(trusted_devices)

    print("\n=== Dataset Validation Demo ===")
    accepted = 0
    rejected = 0

    for _ in range(15):
        telemetry = generate_telemetry()
        sender = telemetry["device_id"]
        receiver = gateway

        try:
            result = channel.send_secure(sender, receiver, telemetry)
            accepted += 1
            print("\nACCEPTED")
            print("Sender:", sender)
            print("Patient:", telemetry["patient_id"])
            print("Challenge:", result["authentication"]["challenge"])
            print("Signature verified:", result["authentication"]["verified"])
        except Exception as e:
            rejected += 1
            print("\nREJECTED")
            print("Sender:", sender)
            print("Patient:", telemetry["patient_id"])
            print("Reason:", e)

    print("\n=== Summary ===")
    print("Accepted:", accepted)
    print("Rejected:", rejected)

    print("\n=== Replay Attack Test ===")
    telemetry = generate_telemetry()
    telemetry["device_id"] = trusted_devices[0]
    try:
        channel.send_secure(trusted_devices[0], gateway, telemetry)
        channel.send_secure(trusted_devices[0], gateway, telemetry)
    except Exception as e:
        print("Replay blocked:", e)

    print("\n=== Revocation Test ===")
    revoked_device = trusted_devices[0]
    channel.revoke_device(revoked_device)
    try:
        telemetry = generate_telemetry()
        telemetry["device_id"] = revoked_device
        channel.send_secure(revoked_device, gateway, telemetry)
    except Exception as e:
        print("Revoked device blocked:", e)


if __name__ == "__main__":
    run_demo()
