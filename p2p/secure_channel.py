import json
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization

from blockchain.ledger import DeviceRegistry
from crypto.certificate_authority import CertificateAuthority
from crypto.key_generation import (
    generate_identity_key_pair,
    serialize_identity_public_key,
    generate_exchange_key_pair,
)
from crypto.key_exchange import derive_shared_secret, derive_session_key
from crypto.encryption import encrypt_message, decrypt_message
from p2p.device_emulator import generate_telemetry, get_unique_devices


class SecureChannel:
    def __init__(self):
        self.registry = DeviceRegistry()
        self.ca = CertificateAuthority()
        self.seen_sequences = set()

    def register_device(self, device_id):
        private_key, public_key = generate_identity_key_pair()
        public_key_hex = serialize_identity_public_key(public_key)

        certificate = self.ca.sign_certificate(device_id, public_key_hex)
        self.registry.register_device(device_id, certificate)

        return {
            "device_id": device_id,
            "public_key": public_key_hex,
            "certificate": certificate
        }

    def register_trusted_devices(self, trusted_devices):
        registered_info = []
        for device_id in trusted_devices:
            registered_info.append(self.register_device(device_id))
        return registered_info

    def verify_device(self, device_id):
        record = self.registry.lookup_device(device_id)

        if not record:
            raise Exception(f"{device_id} is not registered")

        if record["status"] != "active":
            raise Exception(f"{device_id} is revoked")

        certificate = record["certificate"]

        if not self.ca.verify_certificate(certificate):
            raise Exception(f"{device_id} certificate verification failed")

        return certificate

    def establish_session(self):
        # Sender ephemeral key pair
        sender_priv, sender_pub = generate_exchange_key_pair()

        # Receiver ephemeral key pair
        receiver_priv, receiver_pub = generate_exchange_key_pair()

        sender_pub_bytes = sender_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        receiver_pub_bytes = receiver_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        sender_pub_loaded = X25519PublicKey.from_public_bytes(sender_pub_bytes)
        receiver_pub_loaded = X25519PublicKey.from_public_bytes(receiver_pub_bytes)

        sender_shared_secret = derive_shared_secret(sender_priv, receiver_pub_loaded)
        receiver_shared_secret = derive_shared_secret(receiver_priv, sender_pub_loaded)

        sender_session_key = derive_session_key(sender_shared_secret)
        receiver_session_key = derive_session_key(receiver_shared_secret)

        return {
            "sender_pub_hex": sender_pub_bytes.hex(),
            "receiver_pub_hex": receiver_pub_bytes.hex(),
            "sender_session_key": sender_session_key,
            "receiver_session_key": receiver_session_key,
        }

    def send_secure(self, sender, receiver, telemetry):
        # 1. Spoofing protection
        if telemetry["device_id"] != sender:
            raise Exception("Spoofing detected")

        # 2. Blockchain + CA verification
        self.verify_device(sender)
        self.verify_device(receiver)

        # 3. Replay protection
        seq_key = (sender, telemetry["sequence_number"])
        if seq_key in self.seen_sequences:
            raise Exception("Replay attack detected")
        self.seen_sequences.add(seq_key)

        # 4. Establish secure session
        session = self.establish_session()

        # 5. Encrypt and decrypt telemetry
        plaintext = json.dumps({
            "sender": sender,
            "receiver": receiver,
            "telemetry": telemetry
        })

        nonce, ciphertext = encrypt_message(session["sender_session_key"], plaintext)
        decrypted = decrypt_message(session["receiver_session_key"], nonce, ciphertext)

        return {
            "encrypted": {
                "nonce": nonce,
                "ciphertext": ciphertext
            },
            "decrypted": json.loads(decrypted)
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
            print("\n✅ ACCEPTED")
            print("Sender:", sender)
            print("Patient:", telemetry["patient_id"])
            print("Action:", telemetry["action"])
            print("Telemetry:", result["decrypted"]["telemetry"])

        except Exception as e:
            rejected += 1
            print("\n❌ REJECTED")
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