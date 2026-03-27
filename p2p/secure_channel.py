import json

from blockchain.ledger import DeviceRegistry
from crypto.key_generation import (
    generate_identity_key_pair,
    serialize_identity_public_key,
    generate_exchange_key_pair,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from crypto.key_exchange import derive_shared_secret, derive_session_key
from crypto.encryption import encrypt_message, decrypt_message
from p2p.device_emulator import generate_telemetry


class SecureChannel:
    def __init__(self):
        self.registry = DeviceRegistry()
        self.seen_sequences = set()

    def register_device(self, device_id: str):
        _, public_key = generate_identity_key_pair()
        public_key_hex = serialize_identity_public_key(public_key)
        self.registry.register_device(device_id, public_key_hex)

    def verify_device(self, device_id: str):
        record = self.registry.lookup_device(device_id)
        if not record:
            raise Exception(f"{device_id} is not registered in the blockchain registry")
        if record["status"] != "active":
            raise Exception(f"{device_id} is revoked")
        return record

    def establish_session(self):
        # Device A ephemeral exchange keys
        a_priv, a_pub = generate_exchange_key_pair()

        # Device B ephemeral exchange keys
        b_priv, b_pub = generate_exchange_key_pair()

        # Convert B public key into loadable form for A
        b_pub_bytes = b_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        b_pub_loaded = X25519PublicKey.from_public_bytes(b_pub_bytes)

        # Convert A public key into loadable form for B
        a_pub_bytes = a_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        a_pub_loaded = X25519PublicKey.from_public_bytes(a_pub_bytes)

        # Derive shared secrets on both sides
        shared_a = derive_shared_secret(a_priv, b_pub_loaded)
        shared_b = derive_shared_secret(b_priv, a_pub_loaded)

        # Derive session keys
        session_key_a = derive_session_key(shared_a)
        session_key_b = derive_session_key(shared_b)

        return session_key_a, session_key_b

    def send_secure(self, sender: str, receiver: str, telemetry: dict):
        # Step 1: Verify sender and receiver through blockchain registry
        self.verify_device(sender)
        self.verify_device(receiver)

        # Step 2: Replay protection
        seq = telemetry["sequence_number"]
        if seq in self.seen_sequences:
            raise Exception("Replay attack detected")
        self.seen_sequences.add(seq)

        # Step 3: Establish secure session
        session_key_sender, session_key_receiver = self.establish_session()

        # Step 4: Encrypt telemetry
        plaintext = json.dumps(telemetry)
        nonce, ciphertext = encrypt_message(session_key_sender, plaintext)

        # Step 5: Decrypt telemetry
        decrypted = decrypt_message(session_key_receiver, nonce, ciphertext)

        return {
            "encrypted": {
                "nonce": nonce,
                "ciphertext": ciphertext,
            },
            "decrypted": json.loads(decrypted),
        }

    def revoke_device(self, device_id: str):
        self.registry.revoke_device(device_id)


def run_demo():
    channel = SecureChannel()

    # Register devices in blockchain registry
    channel.register_device("deviceA")
    channel.register_device("deviceB")

    # Generate telemetry
    telemetry = generate_telemetry()

    print("\n=== Normal Secure Transmission ===")
    result = channel.send_secure("deviceA", "deviceB", telemetry)
    print("Encrypted payload:")
    print(json.dumps(result["encrypted"], indent=2))
    print("\nDecrypted payload:")
    print(json.dumps(result["decrypted"], indent=2))

    print("\n=== Replay Attack Test ===")
    try:
        channel.send_secure("deviceA", "deviceB", telemetry)
    except Exception as e:
        print("Replay blocked:", e)

    print("\n=== Revocation Test ===")
    channel.revoke_device("deviceA")
    try:
        new_telemetry = generate_telemetry()
        channel.send_secure("deviceA", "deviceB", new_telemetry)
    except Exception as e:
        print("Revoked device blocked:", e)


if __name__ == "__main__":
    run_demo()